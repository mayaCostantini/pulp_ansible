import aiofiles
import asyncio
import hashlib
import json
import logging
import tarfile
import tempfile
import cryptography.x509 as x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from gettext import gettext as _

from sigstore.verify.models import VerificationFailure
from sigstore._internal.oidc import Identity
from sigstore._internal.sct import verify_sct
from sigstore._utils import sha256_streaming
from sigstore_protobuf_specs.dev.sigstore.bundle.v1 import Bundle

from pulpcore.plugin.stages import (
    ContentSaver,
    DeclarativeContent,
    DeclarativeVersion,
    Stage,
)

from pulp_ansible.app.models import (
    AnsibleRepository,
    CollectionVersion,
    CollectionVersionSignature,
    CollectionVersionSigstoreSignature,
    SigstoreSigningService,
)

from django.conf import settings
from django.core.files.storage import default_storage as storage
from pulpcore.plugin.models import SigningService, ProgressReport
from pulpcore.plugin.sync import sync_to_async_iterable, sync_to_async
from pulpcore.plugin.util import gpg_verify
from pulpcore.plugin.exceptions import InvalidSignatureError
from pulp_ansible.app.tasks.utils import get_file_obj_from_tarball
from pulp_ansible.app.sigstoreutils import (
    MissingSigstoreVerificationMaterialsException,
    VerificationFailureException,
)
from rest_framework import serializers

import base64

log = logging.getLogger(__name__)


def verify_signature_upload(data):
    """The task code for verifying collection signature upload."""
    file = data["file"]
    sig_data = file.read().decode()
    file.seek(0)
    collection = data["signed_collection"]
    repository = data.get("repository")
    gpgkey = repository and repository.gpgkey or ""

    artifact = collection.contentartifact_set.select_related("artifact").first().artifact.file.name
    artifact_file = storage.open(artifact)
    with tarfile.open(fileobj=artifact_file, mode="r") as tar:
        manifest = get_file_obj_from_tarball(tar, "MANIFEST.json", artifact_file)
        with tempfile.NamedTemporaryFile(dir=".") as manifest_file:
            manifest_file.write(manifest.read())
            manifest_file.flush()
            try:
                verified = gpg_verify(gpgkey, file, manifest_file.name)
            except InvalidSignatureError as e:
                if gpgkey:
                    raise serializers.ValidationError(
                        _("Signature verification failed: {}").format(e.verified.status)
                    )
                elif settings.ANSIBLE_SIGNATURE_REQUIRE_VERIFICATION:
                    raise serializers.ValidationError(
                        _("Signature verification failed: No key available.")
                    )
                else:
                    # We have no key configured. So we simply accept the signature as is
                    verified = e.verified
                    log.warn(
                        "Collection Signature was accepted without verification. No key available."
                    )

    data["data"] = sig_data
    data["digest"] = file.hashers["sha256"].hexdigest()
    data["pubkey_fingerprint"] = verified.fingerprint
    return data


def verify_sigstore_signature_upload(data):
    """The task code for verifying Sigstore signature upload."""
    collection = data["signed_collection"]
    repository = data.get("repository")
    sigstore_signing_service = repository and repository.sigstore_signing_service
    artifact = collection.contentartifact_set.select_related("artifact").first().artifact.file.name
    artifact_file = storage.open(artifact)
    with tarfile.open(fileobj=artifact_file, mode="r") as tar:
        try:
            sha256sumfile = get_file_obj_from_tarball(
                tar, ".ansible-sign/sha256sum.txt", artifact_file
            )
        except FileNotFoundError as e:
            raise VerificationFailureException(
                "Missing .ansible-sign/sha256sum.txt checksums file in the collection to verify."
            ) from e
        certificate = data["sigstore_x509_certificate"]
        signature = data["data"]
        sigstore_bundle = data.get("sigstore_bundle")
        if sigstore_signing_service.sigstore_bundle and not sigstore_bundle:
            raise MissingSigstoreVerificationMaterialsException(
                "Sigstore signing service for this repository requires "
                "a Sigstore bundle to verify the collection signature."
            )
        # TODO: check if verification is possible
        # without cert and sig and only with sigstore bundle.
        if not sigstore_bundle:
            with tempfile.NamedTemporaryFile(dir=".", delete=False) as manifest_file:
                manifest_file.write(sha256sumfile.read())
            with open(manifest_file.name, mode="rb", buffering=0) as io:
                verification_result = sigstore_signing_service.sigstore_verify(
                    sha256sumfile=io,
                    sha256sumcert=certificate.read().decode(),
                    sha256sumsig=base64.b64encode(signature.read()),
                    sigstore_bundle=None,
                    entry=None,
                )
        else:
            bundle = Bundle().from_json(sigstore_bundle)
            with tempfile.NamedTemporaryFile(dir=".", delete=False) as manifest_file:
                manifest_file.write(sha256sumfile.read())
            with open(manifest_file.name, mode="rb", buffering=0) as io:
                verification_result = sigstore_signing_service.sigstore_verify(
                    sha256sumfile=io,
                    sha256sumcert=None,
                    sha256sumsig=None,
                    sigstore_bundle=bundle,
                    entry=None,
                )

        if isinstance(verification_result, VerificationFailure):
            raise VerificationFailureException(
                "Failed to verify Sigstore signature for collection "
                f"{collection}: {verification_result.reason}"
            )

        print(f"Validated Sigstore signature for collection {collection}")

    data["data"] = signature
    data["sigstore_x509_certificate"] = certificate
    data["sigstore_signing_service"] = sigstore_signing_service

    return data


def sign(repository_href, content_hrefs, signing_service_href):
    """The signing task."""
    repository = AnsibleRepository.objects.get(pk=repository_href)
    if content_hrefs == ["*"]:
        filtered = repository.latest_version().content.filter(
            pulp_type=CollectionVersion.get_pulp_type()
        )
        content = CollectionVersion.objects.filter(pk__in=filtered)
    else:
        content = CollectionVersion.objects.filter(pk__in=content_hrefs)
    signing_service = SigningService.objects.get(pk=signing_service_href)
    filtered_sigs = repository.latest_version().content.filter(
        pulp_type=CollectionVersionSignature.get_pulp_type()
    )
    repos_current_signatures = CollectionVersionSignature.objects.filter(pk__in=filtered_sigs)
    first_stage = CollectionSigningFirstStage(content, signing_service, repos_current_signatures)
    SigningDeclarativeVersion(first_stage, repository).create()


def sigstore_sign(repository_href, content_hrefs, sigstore_signing_service_href):
    """Signing task for Sigstore."""
    repository = AnsibleRepository.objects.get(pk=repository_href)
    if content_hrefs == ["*"]:
        filtered = repository.latest_version().content.filter(
            pulp_type=CollectionVersion.get_pulp_type()
        )
        content = CollectionVersion.objects.filter(pk__in=filtered)
    else:
        content = CollectionVersion.objects.filter(pk__in=content_hrefs)
    sigstore_signing_service = SigstoreSigningService.objects.get(pk=sigstore_signing_service_href)
    filtered_sigs = repository.latest_version().content.filter(
        pulp_type=CollectionVersionSigstoreSignature.get_pulp_type()
    )
    repos_current_signatures = CollectionVersionSigstoreSignature.objects.filter(
        pk__in=filtered_sigs
    )
    first_stage = CollectionSigstoreSigningFirstStage(
        content, sigstore_signing_service, repos_current_signatures
    )
    SigningDeclarativeVersion(first_stage, repository).create()


class SigningDeclarativeVersion(DeclarativeVersion):
    """Custom signature pipeline."""

    def pipeline_stages(self, new_version):
        """The stages for the signing process."""
        pipeline = [
            self.first_stage,  # CollectionSigningFirstStage or CollectionSigstoreSigningFirstStage
            ContentSaver(),
        ]
        return pipeline


class CollectionSigningFirstStage(Stage):
    """
    This stage signs the content and creates CollectionVersionSignatures.
    """

    def __init__(self, content, signing_service, current_signatures):
        """Initialize Signing first stage."""
        super().__init__()
        self.content = content
        self.signing_service = signing_service
        self.repos_current_signatures = current_signatures
        self.semaphore = asyncio.Semaphore(settings.ANSIBLE_SIGNING_TASK_LIMITER)

    async def sign_collection_version(self, collection_version):
        """Signs the collection version."""

        def _extract_manifest():
            cartifact = collection_version.contentartifact_set.select_related("artifact").first()
            artifact_name = cartifact.artifact.file.name
            artifact_file = storage.open(artifact_name)
            with tarfile.open(fileobj=artifact_file, mode="r") as tar:
                manifest = get_file_obj_from_tarball(tar, "MANIFEST.json", artifact_name)
                return manifest.read()

        # Limits the number of subprocesses spawned/running at one time
        async with self.semaphore:
            # We use the manifest to create the signature
            # OpenPGP doesn't take filename into account for signatures, not sure about others
            async with aiofiles.tempfile.NamedTemporaryFile(dir=".", mode="wb") as m:
                manifest_data = await sync_to_async(_extract_manifest)()
                await m.write(manifest_data)
                await m.flush()
                result = await self.signing_service.asign(m.name)
            async with aiofiles.open(result["signature"], "rb") as sig:
                data = await sig.read()
            cv_signature = CollectionVersionSignature(
                data=data.decode(),
                digest=hashlib.sha256(data).hexdigest(),
                signed_collection=collection_version,
                pubkey_fingerprint=self.signing_service.pubkey_fingerprint,
                signing_service=self.signing_service,
            )
            dc = DeclarativeContent(content=cv_signature)
            await self.progress_report.aincrement()
            await self.put(dc)

    async def run(self):
        """Signs collections if they have not been signed with key."""
        tasks = []
        # Filter out any content that already has a signature with pubkey_fingerprint
        current_signatures = CollectionVersionSignature.objects.filter(
            pubkey_fingerprint=self.signing_service.pubkey_fingerprint
        )
        new_content = self.content.exclude(signatures__in=current_signatures)
        ntotal = await sync_to_async(new_content.count)()
        nmsg = _("Signing new CollectionVersions")
        async with ProgressReport(message=nmsg, code="sign.new.signature", total=ntotal) as p:
            self.progress_report = p
            async for collection_version in sync_to_async_iterable(new_content.iterator()):
                tasks.append(asyncio.create_task(self.sign_collection_version(collection_version)))
            await asyncio.gather(*tasks)

        # Add any signatures already present in Pulp if part of content list
        present_content = current_signatures.filter(signed_collection__in=self.content).exclude(
            pk__in=self.repos_current_signatures
        )
        ptotal = await sync_to_async(present_content.count)()
        pmsg = _("Adding present CollectionVersionSignatures")
        async with ProgressReport(message=pmsg, code="sign.present.signature", total=ptotal) as np:
            async for signature in sync_to_async_iterable(present_content.iterator()):
                await np.aincrement()
                await self.put(DeclarativeContent(content=signature))


class CollectionSigstoreSigningFirstStage(Stage):
    """
    This stage signs the content with Sigstore OIDC credentials provided on the Pulp server
    and creates CollectionVersionSigstoreSignatures.
    """

    def __init__(self, content, sigstore_signing_service, current_sigstore_signatures):
        """Initialize Sigstore signing first stage."""
        super().__init__()
        self.content = content
        self.sigstore_signing_service = sigstore_signing_service
        self.repos_current_sigstore_signatures = current_sigstore_signatures
        self.semaphore = asyncio.Semaphore(settings.ANSIBLE_SIGNING_TASK_LIMITER)

    async def sigstore_sign_collection_versions(self, collection_versions):
        """Signs the collection versions with Sigstore."""

        def _extract_manifest(collection_version):
            cartifact = collection_version.contentartifact_set.select_related("artifact").first()
            artifact_name = cartifact.artifact.file.name
            artifact_file = storage.open(artifact_name)
            with tarfile.open(fileobj=artifact_file, mode="r") as tar:
                manifest = get_file_obj_from_tarball(tar, "MANIFEST.json", artifact_name)
                return manifest.read()

        # Prepare ephemeral key pair and certificate and sign the collections asynchronously
        private_key = ec.generate_private_key(ec.SECP384R1())
        with open(self.sigstore_signing_service.credentials_file_path, "r") as credentials_file:
            credentials = json.load(credentials_file)
            client_id, client_secret = (
                credentials["keycloak_client_id"],
                credentials["keycloak_client_secret"],
            )
            if self.sigstore_signing_service.set_keycloak:
                identity_token = self.sigstore_signing_service.keycloak.identity_token(
                    client_id, client_secret, self.sigstore_signing_service.disable_interactive
                )
            else:
                identity_token = self.sigstore_signing_service.issuer.identity_token(
                    client_id, client_secret, self.sigstore_signing_service.disable_interactive
                )
        oidc_identity = Identity(identity_token)

        # Build an X.509 Certificiate Signing Request
        builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.EMAIL_ADDRESS, oidc_identity.proof),
                    ]
                )
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
        )
        certificate_request = builder.sign(private_key, hashes.SHA256())
        certificate_response = self.sigstore_signing_service.fulcio.signing_cert.post(
            certificate_request, identity_token
        )

        # Verify the SCT
        sct = certificate_response.sct
        cert = certificate_response.cert
        chain = certificate_response.chain
        verify_sct(sct, cert, chain, self.sigstore_signing_service.rekor._ct_keyring)

        b64_cert = base64.b64encode(cert.public_bytes(encoding=serialization.Encoding.PEM))

        # Limits the number of subprocesses spawned/running at one time
        async with self.semaphore:
            async for collection_version in sync_to_async_iterable(collection_versions.iterator()):
                # We use the manifest to create the signature
                async with aiofiles.tempfile.NamedTemporaryFile(
                    dir=".", mode="wb", delete=False
                ) as manifest_file:
                    manifest_data = await sync_to_async(_extract_manifest)(collection_version)
                    await manifest_file.write(manifest_data)
                async with aiofiles.open(manifest_file.name, mode="rb", buffering=0) as io:
                    print(io, type(io))
                    input_digest = sha256_streaming(io)
                    result = await self.sigstore_signing_service.sigstore_asign(
                        input_digest, private_key, b64_cert
                    )
                async with aiofiles.open(result["signature"], "rb") as sig:
                    sig_data = await sig.read()
                async with aiofiles.open(result["certificate"], "rb") as cert:
                    cert_data = await cert.read()
                async with aiofiles.open(result["bundle"], "rb") as bundle:
                    bundle_data = await bundle.read()

                cv_signature = CollectionVersionSigstoreSignature(
                    data=sig_data.decode(),
                    digest=hashlib.sha256(sig_data).hexdigest(),
                    signed_collection=collection_version,
                    sigstore_x509_certificate=cert_data,
                    sigstore_x509_certificate_sha256_digest=hashlib.sha256(cert_data).hexdigest(),
                    sigstore_bundle=bundle_data,
                    sigstore_signing_service=self.sigstore_signing_service,
                )
                dc = DeclarativeContent(content=cv_signature)
                await self.progress_report.aincrement()
                await self.put(dc)

    async def run(self):
        """Sign collections with Sigstore if they have not been signed."""
        # Filter out any content that has not been signed with the Sigstore signing service.
        current_signatures = CollectionVersionSigstoreSignature.objects.filter(
            sigstore_signing_service__name=self.sigstore_signing_service.name
        )
        new_content = self.content.exclude(sigstore_signatures__in=current_signatures)
        ntotal = await sync_to_async(new_content.count)()
        msg = _("Signing new CollectionVersions with Sigstore.")
        async with ProgressReport(message=msg, code="sign.new.signature", total=ntotal) as p:
            self.progress_report = p
            await asyncio.create_task(self.sigstore_sign_collection_versions(new_content))

        present_content = current_signatures.filter(signed_collection__in=self.content).exclude(
            pk__in=self.repos_current_sigstore_signatures
        )
        ptotal = await sync_to_async(present_content.count())
        pmsg = _("Adding present CollectionVersionSigstoreSignatures")
        async with ProgressReport(message=pmsg, code="sign.present.signature", total=ptotal) as np:
            async for sigstore_signature in sync_to_async_iterable(present_content.iterator()):
                await np.aincrement()
                await self.put(DeclarativeContent(content=sigstore_signature))
