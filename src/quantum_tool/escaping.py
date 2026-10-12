"""
Escape helpers shared by every writer of scanned values.

Host names, certificate subjects and file names, cipher-suite names and error
texts come from the scanned systems or from a report file, so they are
untrusted. ``clean_text`` makes such a value safe to show at all: it removes
ANSI escape sequences, control characters, Unicode format characters (bidi
overrides and isolates, zero-width characters) and lone surrogates, turns line
breaks and tabs into spaces and truncates to ``MAX_FIELD_CHARS``.

``markdown_text`` builds on it for the Markdown roadmap: HTML characters become
entities, every character with Markdown meaning is backslash-escaped, a value
can never open a block (heading, list item, quote, table row, code fence) and
never leaves a URL, ``www.`` host or e-mail address that a renderer would turn
into a link. ``terminal_text`` is ``clean_text`` for console output. The JSON
report keeps values unchanged and relies on the JSON encoder with
``ensure_ascii`` (every non-ASCII and control character is written as a
``\\uXXXX`` escape).
"""

import re
import unicodedata

MAX_FIELD_CHARS = 256
TRUNCATION_MARK = '...truncated'

_ANSI = re.compile(
    r'\x1b\[[0-?]*[ -/]*[@-~]'               # CSI sequences (colours, cursor moves)
    r'|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?'    # OSC sequences (window title, hyperlinks)
    r'|\x1b[@-Z\\-_]'                         # two-character escapes
    r'|\x9b[0-?]*[ -/]*[@-~]')                # 8-bit CSI
_WHITESPACE_CONTROLS = {'\t', '\n', '\v', '\f', '\r', '\x85', '\u2028', '\u2029'}
_DROPPED_CATEGORIES = {'Cc', 'Cf', 'Cs'}

_HTML = (('&', '&amp;'), ('<', '&lt;'), ('>', '&gt;'))
_MARKDOWN_SPECIAL = set('\\`*_[](){}#|!~$@')
_BLOCK_START = re.compile(r'^([-+]|\d+\.)')
_URL_SCHEME = re.compile(r'://')
_WWW = re.compile(r'(?i)(www)\.')


class Escaped(str):
    """Text that ``markdown_text`` already escaped; it is never escaped twice."""


def clean_text(value, limit=MAX_FIELD_CHARS):
    """Return ``value`` as display-safe text of at most ``limit`` characters."""
    text = value if isinstance(value, str) else str(value)
    text = _ANSI.sub('', text.replace('\r\n', '\n'))
    chars = []
    for char in text:
        if char in _WHITESPACE_CONTROLS:
            chars.append(' ')
        elif unicodedata.category(char) not in _DROPPED_CATEGORIES:
            chars.append(char)
    text = ''.join(chars).strip()
    if len(text) > limit:
        text = text[:limit - len(TRUNCATION_MARK)] + TRUNCATION_MARK
    return text


def terminal_text(value):
    """Text for console output: escape sequences and control characters removed."""
    return clean_text(value)


def _escape_markdown(text):
    for raw, entity in _HTML:
        text = text.replace(raw, entity)
    text = ''.join('\\' + char if char in _MARKDOWN_SPECIAL else char for char in text)
    text = _URL_SCHEME.sub(r':\\/\\/', text)
    text = _WWW.sub(r'\1\\.', text)
    return _BLOCK_START.sub(lambda m: '\\' + m.group(1) if m.group(1) in '-+'
                            else m.group(1)[:-1] + '\\.', text)


def markdown_text(value):
    """Escape ``value`` for inline use in Markdown (table cell, list item, heading).

    Integers and floats are kept as they are; every other value, including
    booleans, None and containers, is rendered as cleaned and escaped text.
    """
    if isinstance(value, Escaped):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    return Escaped(_escape_markdown(clean_text(value)))


def markdown_join(values, separator=', '):
    """Escape each item on its own (so each is truncated separately) and join them."""
    return Escaped(separator.join(str(markdown_text(value)) for value in values or ()))
