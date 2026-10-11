"""Config loading, validation and CIDR target expansion."""

import os
from unittest import mock

import pytest

from quantum_tool import config
from quantum_tool.config import ConfigError, expand_targets, load_config, validate
from quantum_tool.crypto_scanner import CryptoScanner

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SHIPPED_CONFIG = os.path.join(REPO_ROOT, "config", "scan_config.yml")


def write_yaml(tmp_path, text):
    path = tmp_path / "scan.yml"
    path.write_text(text)
    return str(path)


def test_missing_keys_take_defaults():
    cfg = validate({"targets": ["192.0.2.10"]})

    assert cfg["targets"] == ["192.0.2.10"]
    assert cfg["ports"] == [443, 8443, 993, 995]
    assert cfg["timeout"] == 10
    assert cfg["max_workers"] == 20
    assert cfg["max_hosts"] == 1024
    assert cfg["enumerate_ciphers"] is True
    assert cfg["cert_paths"] == []
    assert cfg["output_format"] == "json"
    assert cfg["output_path"] == "reports/"
    assert cfg["bench_iterations"] == 20


def test_defaults_are_not_shared_between_calls():
    first = validate({})
    first["ports"].append(1)
    assert validate({})["ports"] == [443, 8443, 993, 995]


def test_load_config_reads_yaml_and_fills_defaults(tmp_path):
    path = write_yaml(tmp_path, "targets:\n  - example.test\ntimeout: 2.5\n")
    cfg = load_config(path)
    assert cfg["targets"] == ["example.test"]
    assert cfg["timeout"] == 2.5
    assert cfg["max_hosts"] == 1024


def test_empty_file_gives_all_defaults(tmp_path):
    cfg = load_config(write_yaml(tmp_path, ""))
    assert cfg == validate({})


def test_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(str(tmp_path / "absent.yml"))


def test_malformed_yaml_raises_config_error(tmp_path):
    with pytest.raises(ConfigError, match="YAML"):
        load_config(write_yaml(tmp_path, "targets: [unclosed\n"))


def test_top_level_must_be_mapping(tmp_path):
    with pytest.raises(ConfigError, match="mapping"):
        load_config(write_yaml(tmp_path, "- 10.0.0.1\n"))


def test_unknown_key_raises():
    with pytest.raises(ConfigError, match="unknown config key 'colour'"):
        validate({"colour": "blue"})


@pytest.mark.parametrize("port", [0, 70000])
def test_port_out_of_range_raises(port):
    with pytest.raises(ConfigError, match="1..65535"):
        validate({"ports": [443, port]})


def test_port_must_be_integer():
    with pytest.raises(ConfigError, match="ports"):
        validate({"ports": ["443"]})


def test_negative_timeout_raises():
    with pytest.raises(ConfigError, match="timeout"):
        validate({"timeout": -1})


def test_zero_timeout_raises():
    with pytest.raises(ConfigError, match="timeout"):
        validate({"timeout": 0})


def test_output_format_xml_raises():
    with pytest.raises(ConfigError, match="json, markdown, both"):
        validate({"output_format": "xml"})


@pytest.mark.parametrize("fmt", ["json", "markdown", "both"])
def test_output_format_accepted_values(fmt):
    assert validate({"output_format": fmt})["output_format"] == fmt


def test_non_list_targets_raises():
    with pytest.raises(ConfigError, match="targets"):
        validate({"targets": "10.0.1.0/24"})


def test_max_workers_upper_bound():
    with pytest.raises(ConfigError, match="max_workers"):
        validate({"max_workers": 257})


def test_boolean_is_not_accepted_as_integer():
    with pytest.raises(ConfigError, match="max_hosts"):
        validate({"max_hosts": True})


def test_enumerate_ciphers_must_be_bool():
    with pytest.raises(ConfigError, match="enumerate_ciphers"):
        validate({"enumerate_ciphers": "yes"})


def test_small_cidr_expands_to_usable_hosts():
    assert expand_targets(["10.0.1.0/30"], 1024) == ["10.0.1.1", "10.0.1.2"]


def test_slash_32_and_hostname_pass_through():
    # A /32 is a single address; the prefix is dropped so connect() gets a bare IP.
    assert expand_targets(["10.0.1.7/32", "tls.example.test"], 1024) == [
        "10.0.1.7", "tls.example.test",
    ]


def test_slash_31_keeps_both_addresses():
    assert expand_targets(["10.0.1.0/31"], 1024) == ["10.0.1.0", "10.0.1.1"]


def test_duplicate_targets_are_scanned_once():
    assert expand_targets(["10.0.1.1", "10.0.1.0/30"], 1024) == ["10.0.1.1", "10.0.1.2"]


def test_plain_ip_passes_through():
    assert expand_targets(["192.0.2.10"], 1024) == ["192.0.2.10"]


def test_large_cidr_over_max_hosts_raises():
    with pytest.raises(ConfigError, match="max_hosts"):
        expand_targets(["10.0.0.0/16"], 1024)


def test_cidr_with_host_bits_set_raises():
    with pytest.raises(ConfigError, match="10.0.1.5/30"):
        expand_targets(["10.0.1.5/30"], 1024)


def test_max_hosts_counts_all_targets_together():
    with pytest.raises(ConfigError, match="max_hosts"):
        expand_targets(["10.0.1.0/30", "10.0.2.0/30"], 3)


def test_shipped_config_validates():
    cfg = load_config(SHIPPED_CONFIG)
    assert cfg["targets"] == ["10.0.1.0/24", "10.0.2.0/24"]
    assert cfg["ports"] == [443, 8443, 993, 995]
    assert len(expand_targets(cfg["targets"], cfg["max_hosts"])) == 508


def test_scan_all_scans_each_expanded_address_not_the_cidr_string():
    scanner = CryptoScanner({"targets": ["10.0.1.0/30"], "ports": [443], "max_hosts": 1024})
    down = {"status": "unreachable"}
    with mock.patch.object(CryptoScanner, "scan_host", return_value=down) as scan_host:
        scanner.scan_all()

    scanned = sorted(call[0] for call in scan_host.call_args_list)
    assert scanned == [("10.0.1.1", 443), ("10.0.1.2", 443)]


def test_scan_all_uses_default_max_hosts():
    assert CryptoScanner({}).max_hosts == config.DEFAULTS["max_hosts"]
