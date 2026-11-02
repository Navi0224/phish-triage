import json

from phish_triage.cli import main

from conftest import SAMPLES_DIR


def test_analyze_single_file_console(capsys):
    assert main(["analyze", str(SAMPLES_DIR / "04_benign_newsletter.eml")]) == 0
    assert "LIKELY-BENIGN" in capsys.readouterr().out


def test_analyze_json_stdout(capsys):
    assert main(["analyze", str(SAMPLES_DIR / "03_bec_reply_to_mismatch_invoice.eml"), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "likely-phish"


def test_batch_mode_writes_reports(tmp_path, capsys):
    assert main(["analyze", str(SAMPLES_DIR), "-q", "--out-dir", str(tmp_path), "--report-format", "both"]) == 0
    out = capsys.readouterr().out
    assert out.count("likely-phish") == 3 and out.count("likely-benign") == 2
    emls = sorted(SAMPLES_DIR.glob("*.eml"))
    for eml in emls:
        for ext in (".json", ".md", ".html"):
            assert (tmp_path / f"{eml.stem}{ext}").is_file()


def test_missing_path_returns_error(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "nope.eml")]) == 1
    assert "does not exist" in capsys.readouterr().err
