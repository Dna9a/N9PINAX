# tests/test_frontend.py
# Lightweight static checks on the shipped frontend: every HTML page parses,
# and the shared helpers exist in main.js / chrome.js.

from html.parser import HTMLParser
from pathlib import Path

_FRONTEND = Path(__file__).resolve().parent.parent / "Frontend  2"


def _html_files():
    return sorted(_FRONTEND.rglob("*.html"))


def test_frontend_dir_exists():
    assert _FRONTEND.is_dir(), f"missing frontend dir: {_FRONTEND}"


def test_all_html_pages_parse():
    files = _html_files()
    assert files, "no HTML files found"
    for f in files:
        parser = HTMLParser()
        parser.feed(f.read_text(encoding="utf-8"))  # raises on malformed markup


def test_main_js_has_api_function():
    main = (_FRONTEND / "js" / "main.js").read_text(encoding="utf-8")
    assert "function api(" in main
    for helper in ["function connectSSE(", "function downloadFile(", "function requireAuth("]:
        assert helper in main, f"main.js missing {helper}"


def test_login_input_is_text_not_email():
    index = (_FRONTEND / "index.html").read_text(encoding="utf-8")
    # The username 'na9a' is not a valid email, so the field must be type=text.
    assert 'type="email"' not in index


def test_every_page_uses_shared_sidebar():
    pages = ["dashboard", "devices", "scan", "alerts", "reports", "admin", "notes"]
    for p in pages:
        html = (_FRONTEND / "pages" / f"{p}.html").read_text(encoding="utf-8")
        assert '<aside class="sidebar" id="sidebar"></aside>' in html, p
        assert "chrome.js" in html, p


def test_chrome_js_has_notes_link_and_dynamic_badge():
    chrome = (_FRONTEND / "js" / "chrome.js").read_text(encoding="utf-8")
    assert "notes.html" in chrome
    assert "nav-alert-badge" in chrome
