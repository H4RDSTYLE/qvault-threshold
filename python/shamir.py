"""
shamir.py — compatibility shim.

The canonical module is now ``qvault_threshold``.  Please update imports:

    from qvault_threshold import generate, reconstruct, verify, P

This file will be removed in a future version.
"""

import warnings
warnings.warn(
    "Importing from 'shamir' is deprecated — use 'qvault_threshold' instead.",
    DeprecationWarning,
    stacklevel=2,
)

from qvault_threshold import generate, reconstruct, verify, P, Share  # noqa: F401

__all__ = ["generate", "reconstruct", "verify", "P", "Share"]
