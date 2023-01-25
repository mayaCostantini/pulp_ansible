from sigstore._verify.verifier import Verifier
from sigstore._verify.policy import AllOf, Identity, OIDCIssuer
from sigstore._internal.ctfe import CTKeyring
from sigstore._internal.rekor import RekorClient
from sigstore._internal.tuf import TrustUpdater

import logging
log = logging.getLogger(__name__)


DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
DEFAULT_TUF_URL = "https://sigstore-tuf-root.storage.googleapis.com/"


class SigstoreException(Exception):
    """Base class for Sigstore related Exceptions."""

class MissingSigstoreVerificationMaterialsException(SigstoreException):
    """Exception for missing Sigstore signature verification materials."""

class VerificationFailureException(SigstoreException):
    """Exception raised when Sigstore failed to validate an artifact signature."""

def get_verifier(rekor_root_pubkey, rekor_url=DEFAULT_REKOR_URL, tuf_url=DEFAULT_TUF_URL):
    # TODO: Use a private CTLog keyring
    ct_keyring = CTKeyring()
    trust_updater = TrustUpdater(tuf_url)
    fulcio_certificate_chain = trust_updater.get_fulcio_certs()
    rekor_root_pubkey_body = "".join(rekor_root_pubkey.split("-----BEGIN PUBLIC KEY-----")).split("-----END PUBLIC KEY-----")[:-1]
    rekor_root_pubkey = ("-----BEGIN PUBLIC KEY-----" + rekor_root_pubkey_body[0].replace(" ", "\n") + "-----END PUBLIC KEY-----").encode()
    return Verifier(
        rekor=RekorClient(rekor_url, rekor_root_pubkey, ct_keyring),
        fulcio_certificate_chain=fulcio_certificate_chain
    )

# Placeholder. TODO: add verification policies as model fields.
def get_verification_policy():
    return OIDCIssuer