import aiofiles
import asyncio
import hashlib
import logging
import tarfile
import tempfile
from gettext import gettext as _

from sigstore._verify.models import VerificationFailure, VerificationSuccess
from sigstore._internal.rekor.client import RekorBundle

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
from pulp_ansible.app.sigstoreutils import MissingSigstoreVerificationMaterialsException, VerificationFailureException
from rest_framework import serializers

import base64
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
from sigstore._verify.verifier import VerificationMaterials
from pulp_ansible.app.sigstoreutils import get_verifier, get_verification_policy

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
        sha256sumfile = get_file_obj_from_tarball(tar, ".ansible-sign/sha256sum.txt", artifact_file)
        sha256sumsig = get_file_obj_from_tarball(tar, ".ansible-sign/sha256sum.txt.sig", artifact_file)
        sha256sumcert = get_file_obj_from_tarball(tar, ".ansible-sign/sha256sum.txt.crt", artifact_file)
        offline_rekor_entry = get_file_obj_from_tarball(tar, ".ansible-sign/sha256sum.txt.rekor", artifact_file)
        missing = []
        for verification_artifact in [sha256sumfile, sha256sumsig, sha256sumcert]:
            if verification_artifact is None:
                missing.append(verification_artifact)
        if missing:
            raise MissingSigstoreVerificationMaterialsException(f"Missing {missing} for Sigstore signature verification")
        
        bundle = RekorBundle.parse_raw(offline_rekor_entry.read().decode())
        entry = bundle.to_entry()

        verification_result = sigstore_signing_service.sigstore_verify(
            sha256sumfile=sha256sumfile,
            sha256sumcert=sha256sumcert.read().decode(),
            sha256sumsig=base64.b64encode(sha256sumsig.read()),
            offline_rekor_entry=entry
        )

        if isinstance(VerificationFailure, verification_result):
            raise VerificationFailureException(f"Failed to verify Sigstore signature for collection {collection}")

        print(f"Validated Sigstore signature for collection {collection}")
        
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

def sigstore_sign(repository_href, content_hrefs):
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
    filtered_sigstore_sigs = repository.latest_version().content.filter(
        pulp_type=CollectionVersionSigstoreSignature.get_pulp_type()
    )
    repos_current_sigstore_signatures = CollectionVersionSigstoreSignature.objects.filter(pk__in=filter_sigstore_sigs)
    first_stage = CollectionSigstoreSigningFirstStage(content, oidc_identity, repos_current_sigstore_signatures)
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

    async def sigstore_sign_collection_version(self, collection_version):
        """Signs the collection version with Sigstore."""

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
            async with aiofiles.tempfile.NamedTemporaryFile(dir=".", mode="wb") as m:
                manifest_data = await sync_to_async(_extract_manifest)()
                await m.write(manifest_data)
                await m.flush()
                result = await self.sigstore_signing_service.sigstore_asign(m.name)
            async with aiofiles.open(result["signature"], "rb") as sig:
                sig_data = await sig.read()
            async with aiofiles.open(result["sigstore_x509_certificate"], "rb") as cert:
                cert_data = await cert.read()

            cv_signature = CollectionVersionSigstoreSignature(
                data=data.decode(),
                digest=hashlib.sha256(data).hexdigest(),
                signed_collection=collection_version,
                sigstore_x509_certificate=cert_data,
                sigstore_x509_certificate_sha256_digest=hashlib.sha256(cert_data).hexdigest(),
                sigstore_signing_service=self.sigstore_signing_service,
            )
            dc = DeclarativeContent(content=cv_signature)
            await self.progress_report.aincrement()
            await self.put(dc)

    async def run(self):
        """Sign collections with Sigstore if they have not been signed."""
        # TODO: Replace this signing logic by checking for a signature holding 
        # a specific OIDC identity, compliant to new verification policy, etc.
        # Need to add corresponding field to the CollectionVersionSigstoreSignature model.
        tasks = []
        # Temporary: filter out any content that has not been signed with Sigstore.
        current_signatures = CollectionVersionSigstoreSignature.objects.exclude(
        sigstore_x509_certificate_sha256_digest=None
        )
        new_content = self.content.exclude(signatures__in=current_signatures)
        ntotal = await sync_to_async(new_content.count)()
        nmsg = _("Signing new CollectionVersions with Sigstore.")
        async with ProgressReport(message=msg, code="sign.new.signature", total=ntotal) as p:
            self.progress_report = p
            async for collection_version in sync_to_async_iterable(new_content.iterator()):
                tasks.append(asyncio.create_task(self.sigstore_sign_collection_version(collection_version)))
            await asyncio.gather(*tasks)

        present_content = current_signatures.filter(signed_collection__in=self.content).exclude(
            pk__in=self.repos_current_sigstore_signatures
        )
        ptotal = await sync_to_async(present_content.count())
        pmsg = _("Adding present CollectionVersionSigstoreSignatures")
        async with ProgressReport(message=pmsg, code="sign.present.signature", total=ptotal) as np:
            async for sigstore_signature in sync_to_async_iterable(present_content.iterator()):
                await np.aincrement()
                await self.put(DeclarativeContent(content=sigstore_signature))