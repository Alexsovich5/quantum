"""
Write scan reports and migration roadmaps into the output directory.

``write_json`` stores the full scan report (optionally with the roadmap under
``roadmap``) as ``scan-<UTC ts>.json``; ``write_markdown`` renders the roadmap
and an endpoint summary through ``templates/roadmap.md.j2`` into
``roadmap-<UTC ts>.md``. ``write_outputs`` picks the files to write from the
``output_format`` setting (docs/SPEC.md section 5.1). ``read_json`` loads an
earlier scan report for ``roadmap --from-json``.

Every value rendered into the Markdown goes through ``escaping.markdown_text``
(the Jinja2 ``finalize`` hook; lists through the ``md_join`` filter): host
names, suites and file paths come from the scanned environment or from a
report file and must not add headings, rows, links or HTML, nor carry control
or bidi characters. The JSON report is written with ``ensure_ascii``.
"""

import json
import numbers
import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from quantum_tool.certificate_manager import UnreadableFile, read_regular_file
from quantum_tool.escaping import markdown_join, markdown_text
from quantum_tool.crypto_scanner import UNASSESSED_STATUSES, summarise

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
ROADMAP_TEMPLATE = 'roadmap.md.j2'
FILE_TIMESTAMP = '%Y%m%dT%H%M%SZ'
FORMATS = ('json', 'markdown', 'both')
MAX_REPORT_BYTES = 50 * 1024 * 1024


def _file_timestamp(now):
    if now is None:
        now = datetime.utcnow()
    elif now.tzinfo is not None:
        now = (now - now.utcoffset()).replace(tzinfo=None)
    return now.strftime(FILE_TIMESTAMP)


def _output_file(directory, prefix, extension, now):
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, '{}-{}.{}'.format(prefix, _file_timestamp(now), extension))


def write_json(report, directory, roadmap=None, now=None):
    """Write ``report`` (plus ``roadmap`` when given) as JSON; return the file path."""
    data = dict(report)
    if roadmap is not None:
        data['roadmap'] = roadmap
    path = _output_file(directory, 'scan', 'json', now)
    with open(path, 'w', encoding='ascii') as handle:
        json.dump(data, handle, indent=2, sort_keys=True, default=str, ensure_ascii=True)
        handle.write('\n')
    return path


def _environment():
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=False,
                      finalize=markdown_text, trim_blocks=True, lstrip_blocks=True,
                      keep_trailing_newline=True, undefined=StrictUndefined)
    env.filters['md_join'] = markdown_join
    return env


def _endpoint_rows(report):
    risk_by_target = {a.get('target'): a.get('risk_score', 0)
                      for a in report.get('assessments') or []}
    rows = []
    for result in report.get('results') or []:
        target = '{}:{}'.format(result.get('host'), result.get('port'))
        rows.append({
            'target': target,
            'protocol': result.get('protocol') or '-',
            'suite': result.get('negotiated_suite') or result.get('cipher_suite') or '-',
            'risk': risk_by_target.get(target, '-'),
            'findings': len(result.get('vulnerabilities') or []),
        })
    return rows


def _bench_rows(roadmap):
    rows, seen = [], set()
    for phase in roadmap.get('phases') or []:
        bench = phase.get('bench')
        if not bench or bench.get('algorithm') in seen:
            continue
        seen.add(bench.get('algorithm'))
        kem = bench.get('kind') == 'kem'
        rows.append({
            'algorithm': bench.get('algorithm'),
            'kind': bench.get('kind'),
            'public_key_len': bench.get('public_key_len'),
            'secret_key_len': bench.get('secret_key_len'),
            'output_len': bench.get('ciphertext_len' if kem else 'signature_len'),
            'keygen_ms': bench.get('keygen_ms'),
            'op1_ms': bench.get('encap_ms' if kem else 'sign_ms'),
            'op2_ms': bench.get('decap_ms' if kem else 'verify_ms'),
        })
    return rows


def render_markdown(roadmap, report):
    """Return the Markdown roadmap text for ``roadmap`` and ``report``."""
    template = _environment().get_template(ROADMAP_TEMPLATE)
    unassessed = report.get('unassessed') or []
    return template.render(
        roadmap=roadmap,
        phases=roadmap.get('phases') or [],
        report=report,
        summary=report.get('summary') or {},
        endpoints=_endpoint_rows(report),
        unassessed=unassessed,
        incomplete=bool(unassessed) or not report.get('assessments'),
        bench_rows=_bench_rows(roadmap),
    )


def write_markdown(roadmap, report, directory, now=None):
    """Render the Markdown roadmap into ``directory``; return the file path."""
    text = render_markdown(roadmap, report)
    path = _output_file(directory, 'roadmap', 'md', now)
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(text)
    return path


def write_outputs(report, roadmap, directory, fmt, now=None):
    """Write the files ``fmt`` (json | markdown | both) asks for; return their paths."""
    if fmt not in FORMATS:
        raise ValueError('output_format must be one of {}, got {!r}'.format(
            ', '.join(FORMATS), fmt))
    paths = []
    if fmt in ('json', 'both'):
        paths.append(write_json(report, directory, roadmap=roadmap, now=now))
    if fmt in ('markdown', 'both'):
        paths.append(write_markdown(roadmap, report, directory, now=now))
    return paths


def _reject_duplicate_keys(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError('duplicate key {!r}'.format(key))
        data[key] = value
    return data


def _reject_constant(name):
    raise ValueError('non-finite number {}'.format(name))


def _count(data, key):
    value = data.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError('{} must be a non-negative integer'.format(key))
    return value


def _endpoint_list(data, key, statuses=None):
    items = data.get(key, [])
    if not isinstance(items, list):
        raise ValueError('{} must be a list'.format(key))
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get('host'), str) \
                or not isinstance(item.get('port'), numbers.Integral):
            raise ValueError('every {} entry needs a host and a port'.format(key))
        if statuses is not None and item.get('status') not in statuses:
            raise ValueError('{} entries need a status of {}'.format(key, ', '.join(statuses)))
    return items


def read_json(path):
    """Load a scan report written by ``write_json`` and rebuild everything derived.

    Totals, summary and assessments are recomputed from ``results`` (and
    ``unassessed``) instead of being trusted from the file. Raises ValueError
    for a non-regular file or one over MAX_REPORT_BYTES, invalid JSON,
    duplicate keys, NaN or Infinity, or a structure that is not a scan report.
    """
    try:
        raw = read_regular_file(path, MAX_REPORT_BYTES)
    except UnreadableFile as exc:
        raise ValueError(exc.strerror)
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_reject_duplicate_keys,
                          parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise ValueError('not UTF-8: {}'.format(exc))
    except json.JSONDecodeError as exc:
        raise ValueError('invalid JSON: {}'.format(exc))
    if not isinstance(data, dict) or 'results' not in data:
        raise ValueError('not a scan report (no "results" list)')
    results = _endpoint_list(data, 'results')
    unassessed = _endpoint_list(data, 'unassessed', UNASSESSED_STATUSES)
    scan_date = data.get('scan_date')
    report = summarise([dict(r, status='ok') for r in results] + unassessed,
                       scan_date=scan_date if isinstance(scan_date, str) else None)
    report['unreachable'] = _count(data, 'unreachable')
    return report
