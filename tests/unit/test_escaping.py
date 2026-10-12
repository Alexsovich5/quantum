"""The shared escape helpers used by every report writer and the CLI output."""

import re

import pytest

from quantum_tool import escaping

# Inverse of markdown_text for the round-trip checks: undo the HTML entities and the
# backslash escapes, which is what a Markdown renderer does when it displays the text.
_ENTITIES = (("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&"))


def unescaped(markdown):
    """The characters of ``markdown`` that are not preceded by an escaping backslash."""
    chars, i = [], 0
    while i < len(markdown):
        if markdown[i] == "\\":
            i += 2
            continue
        chars.append(markdown[i])
        i += 1
    return "".join(chars)


def displayed(markdown):
    text = re.sub(r"\\(.)", r"\1", markdown)
    for entity, char in _ENTITIES:
        text = text.replace(entity, char)
    return text


@pytest.mark.parametrize("raw, expected", [
    ("plain-host.example", "plain-host.example"),
    ("\x1b[31mred\x1b[0m", "red"),
    ("\x1b]0;title\x07name", "name"),
    ("\x9b31mred", "red"),
    ("a\u202egnp.exe", "agnp.exe"),
    ("zero\u200bwidth\ufeff", "zerowidth"),
    ("iso\u2066late\u2069", "isolate"),
    ("line\nbreak\r\nand\ttab", "line break and tab"),
    ("para\u2028graph\u2029end", "para graph end"),
    ("nul\x00bell\x07", "nulbell"),
    ("lone\ud800surrogate", "lonesurrogate"),
])
def test_clean_text_strips_control_ansi_bidi_and_surrogates(raw, expected):
    assert escaping.clean_text(raw) == expected


def test_clean_text_truncates_to_a_fixed_length():
    cleaned = escaping.clean_text("a" * (escaping.MAX_FIELD_CHARS + 50))

    assert len(cleaned) == escaping.MAX_FIELD_CHARS
    assert cleaned.endswith(escaping.TRUNCATION_MARK)


def test_clean_text_converts_non_strings():
    assert escaping.clean_text(None) == "None"
    assert escaping.clean_text({"k": ["v"]}) == "{'k': ['v']}"


@pytest.mark.parametrize("raw", [
    "](http://evil)", "[x](javascript:alert(1))", "![img](http://evil/x.png)",
    "<script>alert(1)</script>", "x\n# Heading", "a|b", "``code``", "*bold* _em_ ~~del~~",
    "#tag", "!bang", "$x^2$", "{braces}", "&lt;already", "back\\slash",
])
def test_markdown_text_escapes_every_special_character(raw):
    out = escaping.markdown_text(raw)

    for char in "[]()`*_~#|!${}":
        assert char not in unescaped(out), (char, out)
    assert "<" not in out and ">" not in out
    assert "\n" not in out and "\r" not in out
    assert displayed(out) == escaping.clean_text(raw)


@pytest.mark.parametrize("raw, expected", [
    ("- item", "\\- item"),
    ("+ item", "\\+ item"),
    ("> quote", "&gt; quote"),
    ("1. item", "1\\. item"),
    ("12) item", "12\\) item"),
    ("a-b+c 1.2", "a-b+c 1.2"),
])
def test_markdown_text_neutralises_block_starts(raw, expected):
    assert escaping.markdown_text(raw) == expected


@pytest.mark.parametrize("raw", [
    "http://evil.example/x", "HTTPS://evil.example", "javascript://x", "www.evil.example",
    "WWW.evil.example", "user@evil.example",
])
def test_markdown_text_never_leaves_an_autolinkable_url(raw):
    out = escaping.markdown_text(raw)

    assert "://" not in out
    assert "www." not in out.lower()
    assert "@" not in unescaped(out)
    assert displayed(out) == raw


def test_markdown_text_keeps_numbers_and_marks_its_output_as_escaped():
    assert escaping.markdown_text(85) == 85
    assert escaping.markdown_text(0.05) == 0.05
    out = escaping.markdown_text("a|b")
    assert isinstance(out, escaping.Escaped)
    assert escaping.markdown_text(out) is out


def test_markdown_text_escapes_booleans_and_none_as_text():
    assert escaping.markdown_text(True) == "True"
    assert escaping.markdown_text(None) == "None"


def test_markdown_join_escapes_each_item_separately():
    items = ["a|b", "c" * (escaping.MAX_FIELD_CHARS + 10), "d"]

    out = escaping.markdown_join(items)

    assert isinstance(out, escaping.Escaped)
    parts = out.split(", ")
    assert parts[0] == "a\\|b"
    assert parts[1].endswith(escaping.TRUNCATION_MARK)
    assert parts[2] == "d"


def test_terminal_text_strips_escapes_but_does_not_markdown_escape():
    assert escaping.terminal_text("\x1b[2J/etc/ssl/my_cert.pem\n") == "/etc/ssl/my_cert.pem"
