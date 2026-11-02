import json

from phish_triage import scoring
from phish_triage.config import load_config
from phish_triage.models import Finding


def test_weights_applied_and_unknown_rule_is_zero(config):
    findings = scoring.apply_weights([Finding("dmarc_fail", "x"), Finding("not_a_rule", "y")], config)
    assert findings[0].weight == config["weights"]["dmarc_fail"]
    assert findings[1].weight == 0


def test_each_rule_counts_once(config):
    findings = scoring.apply_weights([Finding("spf_fail", "a"), Finding("spf_fail", "b")], config)
    assert scoring.score(findings, config) == config["weights"]["spf_fail"]


def test_score_is_capped(config):
    rules = ["lookalike_domain", "double_extension", "executable_content", "display_name_spoof"]
    findings = scoring.apply_weights([Finding(r, r) for r in rules], config)
    assert scoring.score(findings, config) == 100


def test_verdict_thresholds(config):
    assert scoring.verdict(0, config) == "likely-benign"
    assert scoring.verdict(29, config) == "likely-benign"
    assert scoring.verdict(30, config) == "suspicious"
    assert scoring.verdict(59, config) == "suspicious"
    assert scoring.verdict(60, config) == "likely-phish"


def test_user_config_overrides_single_weight(tmp_path):
    path = tmp_path / "my.json"
    path.write_text(json.dumps({"weights": {"spf_fail": 1}, "thresholds": {"suspicious": 10}}))
    cfg = load_config(path)
    assert cfg["weights"]["spf_fail"] == 1
    assert cfg["weights"]["dmarc_fail"] == load_config()["weights"]["dmarc_fail"]  # others kept
    assert cfg["thresholds"] == {"likely_phish": 60, "suspicious": 10}
