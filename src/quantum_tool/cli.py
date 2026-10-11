"""
Command line entry point: ``scan``, ``certs``, ``bench`` and ``roadmap``.

Options and exit codes follow docs/SPEC.md section 5.5: 0 on success, 1 when
``--fail-on LEVEL`` finds a finding at or above LEVEL or the assessment is
incomplete, 2 on a configuration or usage error. Findings with threat class
``none`` (no change required) never trigger ``--fail-on``.

Incomplete means: an endpoint answered but was not assessed (``no_tls`` or
``error``), a certificate/key file could not be read, or nothing at all was
assessed. Each case is always printed to stderr; with ``--fail-on`` it also
fails the run, so a broken scan cannot pass a CI gate.
"""

import logging
import os
import sys

import click
import yaml

from quantum_tool import certificate_manager, report as report_writer
from quantum_tool.config import ConfigError, DEFAULTS, load_config
from quantum_tool.crypto_scanner import CryptoScanner
from quantum_tool.migration_engine import build_roadmap
from quantum_tool.vulnerability_assessor import assess_certificate, assess_key

DEFAULT_CONFIG = os.path.join('config', 'scan_config.yml')
LEVELS = ('critical', 'high', 'medium', 'low')
LEVEL_RANK = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}

logger = logging.getLogger('quantum_tool.cli')


def threshold_reached(assessments, level):
    """True when any actionable finding in ``assessments`` is at or above ``level``."""
    if level is None:
        return False
    floor = LEVEL_RANK[level]
    return any(
        finding.get('threat_class') != 'none'
        and LEVEL_RANK.get(finding.get('threat_level'), -1) >= floor
        for assessment in assessments
        for finding in assessment.get('findings') or []
    )


def highest_level(assessment):
    """Highest threat level among the actionable findings, or 'none'."""
    levels = [f['threat_level'] for f in assessment.get('findings') or []
              if f.get('threat_class') != 'none']
    if not levels:
        return 'none'
    return max(levels, key=lambda level: LEVEL_RANK.get(level, -1))


def _setup_logging(verbose):
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING,
                        format='%(levelname)s %(name)s: %(message)s')


def _config_error(ctx, exc):
    click.echo('config error: {}'.format(exc), err=True)
    ctx.exit(2)


def _load(ctx, path):
    try:
        return load_config(path)
    except ConfigError as exc:
        _config_error(ctx, exc)


def _format_is_explicit(path):
    """True when the config file itself sets ``output_format``."""
    try:
        with open(path) as handle:
            raw = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError):
        return False
    return isinstance(raw, dict) and 'output_format' in raw


def coverage_problems(assessments, report=None, unreadable=()):
    """Reasons the assessment is incomplete; [] when everything was assessed."""
    problems = []
    report = report or {}
    if report.get('no_tls'):
        problems.append('{} endpoint(s) accepted TCP but completed no TLS 1.2+ handshake'
                        .format(report['no_tls']))
    if report.get('errors'):
        problems.append('{} endpoint(s) failed during the scan'.format(report['errors']))
    for item in unreadable:
        problems.append('cannot read {}: {}'.format(item['path'], item['reason']))
    if not assessments:
        problems.append('nothing was assessed')
    return problems


def _finish(ctx, assessments, fail_on, problems=()):
    for problem in problems:
        click.echo('warning: {} (not assessed)'.format(problem), err=True)
    if threshold_reached(assessments, fail_on):
        click.echo('findings at or above {} found'.format(fail_on), err=True)
        ctx.exit(1)
    if fail_on and problems:
        click.echo('assessment incomplete; failing --fail-on {}'.format(fail_on), err=True)
        ctx.exit(1)


def _run_scan(ctx, cfg):
    try:
        return CryptoScanner(cfg).scan_all()
    except ConfigError as exc:
        _config_error(ctx, exc)


def _inventory(paths):
    """Certificates, keys and unreadable entries from each path.

    A directory is scanned recursively; a file named directly must be readable
    and hold a certificate or key (OSError / ValueError otherwise).
    """
    certificates, keys, unreadable, seen = [], [], [], set()
    for path in paths:
        if os.path.isdir(path):
            found = certificate_manager.scan_directory(path)
        else:
            found = certificate_manager.load_file(path)
        for cert in found['certificates']:
            if cert['fingerprint_sha256'] not in seen:
                seen.add(cert['fingerprint_sha256'])
                certificates.append(cert)
        keys.extend(found['keys'])
        unreadable.extend(found.get('unreadable') or [])
    return certificates, keys, unreadable


def _file_assessments(paths):
    certificates, keys, unreadable = _inventory(paths)
    return ([assess_certificate(c) for c in certificates]
            + [assess_key(k) for k in keys]), unreadable


def _file_error(exc):
    """One-line message for a file error: path and reason, no traceback."""
    if isinstance(exc, OSError) and exc.filename is not None:
        return '{}: {}'.format(exc.filename, exc.strerror or exc)
    return str(exc)


def _print_endpoints(report):
    risk = {a['target']: a for a in report.get('assessments') or []}
    for result in report.get('results') or []:
        target = '{}:{}'.format(result['host'], result['port'])
        assessment = risk.get(target, {})
        click.echo('{:<28} {:<8} {:<34} risk {:>3}  {}'.format(
            target, result.get('protocol') or '-', result.get('negotiated_suite') or '-',
            assessment.get('risk_score', 0), highest_level(assessment)))
    if report.get('unreachable'):
        click.echo('{} endpoint(s) unreachable'.format(report['unreachable']))


def _print_paths(paths):
    for path in paths:
        click.echo('wrote {}'.format(path))


def _write(ctx, result, roadmap, directory, fmt):
    try:
        paths = report_writer.write_outputs(result, roadmap, directory, fmt)
    except OSError as exc:
        click.echo('error: cannot write reports: {}'.format(_file_error(exc)), err=True)
        ctx.exit(2)
    _print_paths(paths)


def _bench_table(results):
    lines = ['{:<30} {:<4} {:>8} {:>8} {:>8} {:>10} {:>10} {:>10}'.format(
        'algorithm', 'kind', 'pk_B', 'sk_B', 'ct/sig_B', 'keygen_ms', 'enc/sig_ms',
        'dec/ver_ms')]
    for r in results:
        kem = r['kind'] == 'kem'
        lines.append('{:<30} {:<4} {:>8} {:>8} {:>8} {:>10.3f} {:>10.3f} {:>10.3f}'.format(
            r['algorithm'], r['kind'], r['public_key_len'], r['secret_key_len'],
            r['ciphertext_len' if kem else 'signature_len'], r['keygen_ms'],
            r['encap_ms' if kem else 'sign_ms'], r['decap_ms' if kem else 'verify_ms']))
    return '\n'.join(lines)


def _bench(ctx, names, iterations):
    from quantum_tool.algorithms import benchmark
    try:
        return benchmark.run(list(names or benchmark.DEFAULT_ALGORITHMS), iterations)
    except ValueError as exc:
        click.echo('error: {}'.format(exc), err=True)
        ctx.exit(2)


config_option = click.option(
    '-c', '--config', 'config_path', default=DEFAULT_CONFIG, show_default=True,
    type=click.Path(dir_okay=False), help='YAML scan configuration.')
output_option = click.option(
    '-o', '--output', 'output_dir', type=click.Path(file_okay=False),
    help='Directory for reports; overrides output_path.')
no_enum_option = click.option(
    '--no-enum', is_flag=True, help='Skip per-cipher enumeration (overrides enumerate_ciphers).')
fail_on_option = click.option(
    '--fail-on', type=click.Choice(LEVELS), default=None,
    help='Exit 1 when any finding is at or above LEVEL.')
verbose_option = click.option('-v', '--verbose', is_flag=True, help='Log at DEBUG level.')


@click.group()
def main():
    """Inventory quantum-vulnerable cryptography and plan its migration."""


@main.command()
@config_option
@no_enum_option
@output_option
@fail_on_option
@verbose_option
@click.pass_context
def scan(ctx, config_path, no_enum, output_dir, fail_on, verbose):
    """Scan the configured TLS endpoints and write the report."""
    _setup_logging(verbose)
    cfg = _load(ctx, config_path)
    if no_enum:
        cfg['enumerate_ciphers'] = False
    result = _run_scan(ctx, cfg)
    roadmap = build_roadmap(result['assessments'])
    _print_endpoints(result)
    _write(ctx, result, roadmap, output_dir or cfg['output_path'], cfg['output_format'])
    _finish(ctx, result['assessments'], fail_on,
            coverage_problems(result['assessments'], report=result))


@main.command()
@config_option
@fail_on_option
@verbose_option
@click.argument('paths', metavar='[PATH]...', nargs=-1, type=click.Path(exists=True))
@click.pass_context
def certs(ctx, config_path, fail_on, verbose, paths):
    """List certificates and private keys under PATH (default: cert_paths)."""
    _setup_logging(verbose)
    if not paths:
        paths = _load(ctx, config_path)['cert_paths']
    try:
        certificates, keys, unreadable = _inventory(paths)
    except (OSError, ValueError) as exc:
        click.echo('error: {}'.format(_file_error(exc)), err=True)
        ctx.exit(2)

    assessments = []
    for cert in certificates:
        assessment = assess_certificate(cert)
        assessments.append(assessment)
        key = '{}-{}'.format(cert['key_type'], cert['curve'] or cert['key_bits'])
        click.echo('certificate {:<50} {:<18} {:<8} risk {:>3}  {}'.format(
            cert['source'], key, cert['signature_hash'], assessment['risk_score'],
            highest_level(assessment)))
    for item in keys:
        assessment = assess_key(item)
        assessments.append(assessment)
        detail = item['curve'] or item['key_bits'] or '-'
        key = '{}-{}'.format(item['key_type'], detail) if detail != '-' else item['key_type']
        click.echo('key         {:<50} {:<18} {:<8} risk {:>3}  {}'.format(
            item['source'], key, '-', assessment['risk_score'], highest_level(assessment)))
    click.echo('{} certificate(s), {} key(s)'.format(len(certificates), len(keys)))
    _finish(ctx, assessments, fail_on, coverage_problems(assessments, unreadable=unreadable))


@main.command()
@click.option('-n', '--iterations', type=click.IntRange(min=1),
              default=DEFAULTS['bench_iterations'], show_default=True,
              help='Repetitions per operation.')
@click.option('--alg', 'algorithms', multiple=True, metavar='NAME',
              help='liboqs mechanism to measure; repeatable (default: roadmap replacements).')
@verbose_option
@click.pass_context
def bench(ctx, iterations, algorithms, verbose):
    """Measure key sizes and operation times of post-quantum replacements."""
    _setup_logging(verbose)
    click.echo(_bench_table(_bench(ctx, algorithms, iterations)))


@main.command()
@config_option
@click.option('--from-json', 'from_json', type=click.Path(exists=True, dir_okay=False),
              help='Build the roadmap from an earlier scan report instead of scanning.')
@no_enum_option
@output_option
@fail_on_option
@verbose_option
@click.pass_context
def roadmap(ctx, config_path, from_json, no_enum, output_dir, fail_on, verbose):
    """Scan (or load a report), assess certificate files, benchmark and plan migration."""
    _setup_logging(verbose)
    cfg = _load(ctx, config_path)
    if no_enum:
        cfg['enumerate_ciphers'] = False

    if from_json:
        try:
            result = report_writer.read_json(from_json)
        except (OSError, ValueError) as exc:
            click.echo('error: {} is not a usable scan report: {}'.format(
                from_json, _file_error(exc)), err=True)
            ctx.exit(2)
    else:
        result = _run_scan(ctx, cfg)

    try:
        file_assessments, unreadable = _file_assessments(cfg['cert_paths'])
    except (OSError, ValueError) as exc:
        _config_error(ctx, _file_error(exc))
    result['assessments'] = list(result['assessments']) + file_assessments

    plan = build_roadmap(result['assessments'],
                         bench=_bench(ctx, None, cfg['bench_iterations']))
    fmt = cfg['output_format']
    if fmt == DEFAULTS['output_format'] and not _format_is_explicit(config_path):
        fmt = 'both'
    _print_endpoints(result)
    click.echo('{} migration phase(s)'.format(len(plan['phases'])))
    _write(ctx, result, plan, output_dir or cfg['output_path'], fmt)
    _finish(ctx, result['assessments'], fail_on,
            coverage_problems(result['assessments'], report=result, unreadable=unreadable))


if __name__ == '__main__':  # pragma: no cover
    sys.exit(main())
