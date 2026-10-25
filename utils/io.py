"""Tiny file helpers. Kept here so tests can mock them."""

import os


def read_token_from_file(path: str) -> str:
    """Read a JWT from a file. Strips whitespace and BOM. Validates basic shape."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Token file not found: {path}")

    # utf-8-sig strips a UTF-8 BOM if present, and reads plain UTF-8 fine.
    # JWTs are ASCII (base64url) so this works regardless of source encoding.
    with open(path, 'r', encoding='utf-8-sig') as f:
        token = f.read().strip()

    if token.count('.') != 2:
        raise ValueError(
            f"Input does not look like a JWT (expected 2 separators, got {token.count('.')}). "
            "Token contents are omitted from this error."
        )

    return token


def read_text_file(path: str) -> str:
    """Read a text file. UTF-8 with BOM handling. Raises FileNotFoundError if missing."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, 'r', encoding='utf-8-sig') as f:
        return f.read()