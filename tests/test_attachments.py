import io
import zipfile

from phish_triage.detectors.attachments import (MAGIC_OLE, detect_attachments, extensions, has_double_extension,
                                                has_office_macro, hash_bytes, inspect_attachment, is_executable)
from phish_triage.models import Attachment

from conftest import make_context, make_eml, rule_ids


def _zip(names):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in names:
            z.writestr(n, b"placeholder")
    return buf.getvalue()


def test_hashes_match_known_values():
    h = hash_bytes(b"abc")
    assert h["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert h["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert h["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_extensions_and_double_extension(config):
    risky, decoys = set(config["risky_extensions"]), set(config["decoy_extensions"])
    assert extensions("Invoice.PDF.exe") == [".pdf", ".exe"]
    assert has_double_extension("invoice.pdf.exe", risky, decoys)
    assert has_double_extension("scan.jpg.html", risky, decoys)
    assert not has_double_extension("report.v2.pdf", risky, decoys)
    assert not has_double_extension("setup.exe", risky, decoys)


def test_macro_detection():
    assert has_office_macro(_zip(["word/document.xml", "word/vbaProject.bin"]))
    assert not has_office_macro(_zip(["word/document.xml"]))
    assert has_office_macro(MAGIC_OLE + b"\x00" * 20 + b"_VBA_PROJECT")
    assert not has_office_macro(MAGIC_OLE + b"\x00" * 20)
    assert not has_office_macro(b"PK\x03\x04 broken zip")


def test_executable_magic():
    assert is_executable(b"MZ\x90\x00")
    assert is_executable(b"\x7fELF...")
    assert not is_executable(b"%PDF-1.7")


def test_inspect_attachment_flags(config):
    info = inspect_attachment(Attachment("Payment.pdf.exe", "application/octet-stream", b"MZ..."), config)
    assert set(info["flags"]) == {"double_extension", "risky_attachment_type", "executable_content"}
    assert info["size"] == 5 and len(info["sha256"]) == 64


def test_iso_and_html_attachments_are_risky():
    ctx = make_context(make_eml(attachments=[("scan.iso", b"x"), ("statement.html", b"<html>")]))
    findings = detect_attachments(ctx)
    assert rule_ids(findings) == {"risky_attachment_type"}
    assert len(findings[0].evidence) == 2


def test_benign_pdf_not_flagged():
    ctx = make_context(make_eml(attachments=[("report.pdf", b"%PDF-1.4 test")]))
    assert detect_attachments(ctx) == []
