"""Load and validate the scanner's YAML configuration and expand CIDR targets."""

import copy
import ipaddress
import numbers

import yaml

OUTPUT_FORMATS = ("json", "markdown", "both")

DEFAULTS = {
    "targets": [],
    "ports": [443, 8443, 993, 995],
    "timeout": 10,
    "max_workers": 20,
    "max_hosts": 1024,
    "enumerate_ciphers": True,
    "cert_paths": [],
    "output_format": "json",
    "output_path": "reports/",
    "bench_iterations": 20,
}


class ConfigError(ValueError):
    """Raised when the configuration file is missing, malformed or invalid."""


def load_config(path):
    """Read a YAML config file and return the validated config with defaults filled in."""
    try:
        with open(path) as handle:
            raw = yaml.safe_load(handle)
    except OSError as exc:
        raise ConfigError("cannot read config file {}: {}".format(path, exc))
    except yaml.YAMLError as exc:
        raise ConfigError("invalid YAML in {}: {}".format(path, exc))
    if raw is None:
        raw = {}
    return validate(raw)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _require_int(cfg, key, low, high=None):
    value = cfg[key]
    if not _is_int(value) or value < low or (high is not None and value > high):
        bound = "{}..{}".format(low, high) if high is not None else ">= {}".format(low)
        raise ConfigError("{} must be an integer {}, got {!r}".format(key, bound, value))


def _require_str_list(cfg, key):
    value = cfg[key]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError("{} must be a list of strings, got {!r}".format(key, value))


def validate(raw):
    """Check a config mapping and return a new dict with defaults for missing keys."""
    if not isinstance(raw, dict):
        raise ConfigError("config must be a mapping of keys to values, got {!r}".format(raw))

    for key in raw:
        if key not in DEFAULTS:
            raise ConfigError("unknown config key {!r} (allowed: {})".format(
                key, ", ".join(sorted(DEFAULTS))))

    cfg = copy.deepcopy(DEFAULTS)
    cfg.update(raw)

    _require_str_list(cfg, "targets")

    ports = cfg["ports"]
    if not isinstance(ports, list):
        raise ConfigError("ports must be a list of integers, got {!r}".format(ports))
    for port in ports:
        if not _is_int(port) or not 1 <= port <= 65535:
            raise ConfigError("ports entries must be integers 1..65535, got {!r}".format(port))

    timeout = cfg["timeout"]
    if (not isinstance(timeout, numbers.Real) or isinstance(timeout, bool)
            or timeout <= 0):
        raise ConfigError("timeout must be a number of seconds > 0, got {!r}".format(timeout))

    _require_int(cfg, "max_workers", 1, 256)
    _require_int(cfg, "max_hosts", 1)
    _require_int(cfg, "bench_iterations", 1)

    if not isinstance(cfg["enumerate_ciphers"], bool):
        raise ConfigError("enumerate_ciphers must be true or false, got {!r}".format(
            cfg["enumerate_ciphers"]))

    _require_str_list(cfg, "cert_paths")

    if cfg["output_format"] not in OUTPUT_FORMATS:
        raise ConfigError("output_format must be one of {}, got {!r}".format(
            ", ".join(OUTPUT_FORMATS), cfg["output_format"]))

    if not isinstance(cfg["output_path"], str) or not cfg["output_path"]:
        raise ConfigError("output_path must be a non-empty string, got {!r}".format(
            cfg["output_path"]))

    return cfg


def _network_hosts(network):
    """Usable addresses of a network: network/broadcast skipped except for /31, /32."""
    if network.num_addresses <= 2:
        return list(network)
    return list(network.hosts())


def _host_count(network):
    if network.num_addresses <= 2:
        return network.num_addresses
    return network.num_addresses - 2


def expand_targets(targets, max_hosts):
    """Turn hostnames, IPs and CIDR blocks into a de-duplicated list of scan addresses.

    Raises ConfigError if a CIDR has host bits set or the total exceeds max_hosts.
    """
    networks = []
    total = 0
    for target in targets:
        if "/" in target:
            try:
                network = ipaddress.ip_network(target, strict=True)
            except ValueError as exc:
                raise ConfigError("invalid CIDR target {!r}: {}".format(target, exc))
            networks.append(network)
            total += _host_count(network)
        else:
            networks.append(target)
            total += 1
        if total > max_hosts:
            raise ConfigError(
                "targets expand to more than max_hosts={} addresses (reached at {!r})".format(
                    max_hosts, target))

    expanded = []
    seen = set()
    for item in networks:
        hosts = [str(a) for a in _network_hosts(item)] if not isinstance(item, str) else [item]
        for host in hosts:
            if host not in seen:
                seen.add(host)
                expanded.append(host)
    return expanded
