from sigstore._internal.tuf import (
    DEFAULT_TUF_URL,
    STAGING_TUF_URL,
    _get_dirs,
    TrustUpdater,
    Updater,
)
from sigstore._utils import read_embedded
from tuf.ngclient import Updater

import logging
import requests
import time
import urllib.parse
import webbrowser

log = logging.getLogger(__name__)


class CustomTrustUpdater(TrustUpdater):
    """TrustUpdater with support for custom TUF roots."""
    
    def __init__(self, url: str) -> None:
        """Initialize a trust updater from a (custom) TUF root URL."""
        self._repo_url = url
        self._updater: Updater | None = None

        self._metadata_dir, self._targets_dir = _get_dirs(url)

        tuf_root = self._metadata_dir / "root.json"
        if not tuf_root.exists():                
            if self._repo_url == STAGING_TUF_URL:
                fname = "staging-root.json"
            else:
                fname = "root.json"

            self._metadata_dir.mkdir(parents=True, exist_ok=True)
            root_json = read_embedded(fname)
            with tuf_root.open("wb") as io:
                io.write(root_json)

        self._targets_dir.mkdir(parents=True, exist_ok=True)

        log.debug(f"TUF metadata: {self._metadata_dir}")
        log.debug(f"TUF targets cache: {self._targets_dir}")
