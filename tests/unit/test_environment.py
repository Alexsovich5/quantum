import ssl

import cffi
import setuptools
import wheel
from cryptography.hazmat.backends.openssl import backend


def test_stdlib_ssl_links_debian_openssl():
    assert ssl.OPENSSL_VERSION.startswith("OpenSSL 1.1.1d")


def test_cryptography_is_built_against_system_openssl():
    assert backend.openssl_version_text().startswith("OpenSSL 1.1.1d")


def test_build_tools_are_pinned_versions():
    assert setuptools.__version__ == "47.1.1"
    assert wheel.__version__ == "0.34.2"
    assert cffi.__version__ == "1.14.0"
