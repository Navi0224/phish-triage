"""Attachment analysis: hashing and static inspection.

Safety: attachments stay as bytes in memory. We compute hashes and look at
file names and the first few bytes. Office documents are ZIP files; we read
the ZIP's *list of file names* (``namelist``) but never extract or open the
content, so a zip bomb or malicious macro can't do anything.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import PurePath
from typing import Any

from ..models import Attachment, Finding
from .context import Context

# Magic bytes at the start of a file reveal its real type regardless of name.
MAGIC_MZ = b"MZ"  # Windows PE executable (.exe/.dll)
MAGIC_ELF = b"\x7fELF"  # Linux executable
MAGIC_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # legacy Office (.doc/.xls) container
MAGIC_ZIP = b"PK\x03\x04"  # ZIP, also used by .docx/.xlsx/.docm
# Name of the stream that holds VBA macros inside Office files.
VBA_MARKERS = (b"_VBA_PROJECT", b"VBA/", b"vbaProject.bin")


def hash_bytes(data: bytes) -> dict[str, str]:
    """MD5, SHA-1 and SHA-256. MD5/SHA-1 are kept because many threat-intel feeds still use them."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def extensions(filename: str) -> list[str]:
    """All extensions, lower-case: ``Invoice.PDF.exe`` -> ``['.pdf', '.exe']``."""
    return [s.lower() for s in PurePath(filename.strip().rstrip(".")).suffixes]


def has_double_extension(filename: str, risky: set[str], decoys: set[str]) -> bool:
    """True for names like ``invoice.pdf.exe``: a harmless-looking extension followed by a risky one.

    Windows hides known extensions by default, so the user sees "invoice.pdf".
    """
    exts = extensions(filename)
    return len(exts) >= 2 and exts[-1] in risky and exts[-2] in decoys


def has_office_macro(data: bytes) -> bool:
    """Simple static check for VBA macros in OOXML (zip) or legacy OLE Office files."""
    if data.startswith(MAGIC_ZIP):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                return any(name.lower().endswith("vbaproject.bin") for name in zf.namelist())
        except zipfile.BadZipFile:
            return False
    if data.startswith(MAGIC_OLE):
        return any(marker in data for marker in VBA_MARKERS)
    return False


def is_executable(data: bytes) -> bool:
    return data.startswith(MAGIC_MZ) or data.startswith(MAGIC_ELF)


def inspect_attachment(att: Attachment, config: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-friendly summary of one attachment, including its flags."""
    risky = set(config.get("risky_extensions", []))
    decoys = set(config.get("decoy_extensions", []))
    exts = extensions(att.filename)
    flags = []
    if has_double_extension(att.filename, risky, decoys):
        flags.append("double_extension")
    if exts and exts[-1] in risky:
        flags.append("risky_attachment_type")
    if has_office_macro(att.data):
        flags.append("office_macro")
    if is_executable(att.data):
        flags.append("executable_content")
    return {
        "filename": att.filename,
        "content_type": att.content_type,
        "size": len(att.data),
        **hash_bytes(att.data),
        "flags": flags,
    }


_TITLES = {
    "double_extension": "Attachment uses a double extension",
    "risky_attachment_type": "Risky attachment file type",
    "office_macro": "Office document contains VBA macros",
    "executable_content": "Attachment is an executable (by file header)",
}


def detect_attachments(ctx: Context) -> list[Finding]:
    """Turn per-attachment flags into one finding per flag type."""
    by_flag: dict[str, list[str]] = {}
    for att in ctx.email.attachments:
        info = inspect_attachment(att, ctx.config)
        for flag in info["flags"]:
            by_flag.setdefault(flag, []).append(f"{att.filename} (sha256 {info['sha256']})")
    return [Finding(flag, _TITLES[flag], "", evidence) for flag, evidence in by_flag.items()]
