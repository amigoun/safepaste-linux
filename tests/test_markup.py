"""Tests for safepaste.markup: what a rich representation hides from its text."""

from __future__ import annotations

from safepaste.markup import hidden_parts


def test_html_yields_what_does_not_render_and_not_the_text() -> None:
    html = (
        "<html><head><style>td {color: red}</style>"
        '<script src="app.js">var build = 7;</script></head>'
        "<body><!-- reviewed by ops -->"
        '<p class="note">Visible words</p>'
        '<a href="https://ci.example/run?id=1">report</a></body></html>'
    )
    parts = hidden_parts("public.html", html).splitlines()

    assert 'href="https://ci.example/run?id=1"' in parts
    assert 'src="app.js"' in parts and 'class="note"' in parts
    assert "td {color: red}" in parts and "var build = 7;" in parts
    assert "reviewed by ops" in parts
    assert not any("Visible words" in p or "report" == p for p in parts)


def test_html_attributes_are_read_in_every_quoting_and_unescaped() -> None:
    html = (
        "<a HREF='https://x.example/?a=1&amp;token=abc'>t</a>"
        '<td class=xl65 x:num="5">5</td>'
    )
    parts = hidden_parts("text/html", html).splitlines()
    assert parts == [
        'HREF="https://x.example/?a=1&token=abc"',
        'class="xl65"',
        'x:num="5"',
    ]


def test_html_inline_media_is_left_out_and_the_rest_kept() -> None:
    blob = "iVBORw0KGgo" + "A" * 50_000 + "=="
    html = f'<img src="data:image/png;base64,{blob}"><a href="https://x.example/?t=1">t</a>'
    out = hidden_parts("public.html", html)
    assert blob not in out
    assert 'href="https://x.example/?t=1"' in out.splitlines()


def test_html_repeated_attributes_are_kept_once() -> None:
    html = '<tr><td class="xl65">1</td></tr>' * 5_000
    assert hidden_parts("public.html", html).splitlines().count('class="xl65"') == 1


def test_an_unclosed_html_comment_runs_to_the_end() -> None:
    out = hidden_parts("public.html", '<p>x</p><!-- token is <a href="y">')
    assert 'token is <a href="y">' in out.splitlines()


def test_rtf_yields_field_instructions_with_escapes_decoded() -> None:
    rtf = (
        r"{\rtf1\ansi Visible "
        r'{\field{\*\fldinst{HYPERLINK "https://x.example/?token=ab\'3dc\\d"}}{\fldrslt link}}'
        r' and {\field{\*\fldinst HYPERLINK "https://y.example/\u8364?" }{\fldrslt y}}}'
    )
    assert hidden_parts("public.rtf", rtf).splitlines() == [
        'HYPERLINK "https://x.example/?token=ab=c\\d"',
        'HYPERLINK "https://y.example/\u20ac"',
    ]


def test_a_kind_it_cannot_read_is_none() -> None:
    assert hidden_parts("public.png", "anything") is None


def test_markup_not_read_in_time_is_none() -> None:
    assert hidden_parts("public.html", '<a href="x">t</a>', timeout=0) is None
