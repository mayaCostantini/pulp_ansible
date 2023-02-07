from sigstore.verify.verifier import Verifier
from sigstore.verify.policy import AllOf, Identity, OIDCIssuer
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
    # Placeholder
    # TODO: Add support for custom Rekor instances / TUF URLs
    return Verifier.production()