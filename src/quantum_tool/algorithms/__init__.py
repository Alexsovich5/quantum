"""
Post-quantum algorithm wrappers over liboqs-python.

liboqs-python 0.3.0 frees the native OQS_KEM / OQS_SIG struct and only then
reads ``length_secret_key`` from it to cleanse the secret key, a
use-after-free (docs/SPEC.md section 11). The ``Safe*`` subclasses below
read the length and cleanse the key first, then free the struct, and ignore
a second call. Every wrapper in this package is built on them.
"""

import ctypes as ct

import oqs


def available():
    """Return the KEM and signature mechanisms enabled in the linked liboqs."""
    return {
        'kem': list(oqs.get_enabled_KEM_mechanisms()),
        'sig': list(oqs.get_enabled_sig_mechanisms()),
    }


def _cleanse_then_free(obj, handle, free_fn):
    if getattr(obj, '_freed', False):
        return
    secret_key = getattr(obj, 'secret_key', None)
    if secret_key is not None:
        length = handle.contents.length_secret_key
        oqs.native().OQS_MEM_cleanse(ct.byref(secret_key), ct.c_size_t(length))
    free_fn(handle)
    obj._freed = True


class SafeKeyEncapsulation(oqs.KeyEncapsulation):
    """KeyEncapsulation whose free() cleanses before freeing and is idempotent."""

    def free(self):
        _cleanse_then_free(self, self._kem, oqs.native().OQS_KEM_free)


class SafeSignature(oqs.Signature):
    """Signature whose free() cleanses before freeing and is idempotent."""

    def free(self):
        _cleanse_then_free(self, self._sig, oqs.native().OQS_SIG_free)
