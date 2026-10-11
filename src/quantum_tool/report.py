"""
Write scan reports and migration roadmaps into the output directory.

``write_json`` stores the full scan report (optionally with the roadmap under
``roadmap``) as ``scan-<UTC ts>.json``; ``write_markdown`` renders the roadmap
and an endpoint summary through ``templates/roadmap.md.j2`` into
``roadmap-<UTC ts>.md``. ``write_outputs`` picks the files to write from the
``output_format`` setting (docs/SPEC.md section 5.1).
"""

import json
import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, StrictUndefined

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
ROADMAP_TEMPLATE = 'roadmap.md.j2'
FILE_TIMESTAMP = '%Y%m%dT%H%M%SZ'
FORMATS = ('json', 'markdown', 'both')


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
    with open(path, 'w') as handle:
        json.dump(data, handle, indent=2, sort_keys=True, default=str)
        handle.write('\n')
    return path


def _environment():
    return Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=False,
                       trim_blocks=True, lstrip_blocks=True,
                       keep_trailing_newline=True, undefined=StrictUndefined)


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
    return template.render(
        roadmap=roadmap,
        phases=roadmap.get('phases') or [],
        report=report,
        summary=report.get('summary') or {},
        endpoints=_endpoint_rows(report),
        bench_rows=_bench_rows(roadmap),
    )


def write_markdown(roadmap, report, directory, now=None):
    """Render the Markdown roadmap into ``directory``; return the file path."""
    text = render_markdown(roadmap, report)
    path = _output_file(directory, 'roadmap', 'md', now)
    with open(path, 'w') as handle:
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
