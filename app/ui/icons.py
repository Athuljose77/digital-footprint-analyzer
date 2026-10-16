"""Inline SVG line icons (teal, reference-style) with no asset files.

Icons are rendered from embedded SVG documents via QtSvg, so they scale
cleanly and never depend on system emoji/font coverage.
"""

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtSvg import QSvgRenderer

ACCENT = "#2dd4bf"

_ICONS = {
    "home": (
        '<path d="M4 11l8-7 8 7" fill="none" stroke="{c}" stroke-width="2" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
        '<path d="M6 9.5V20h12V9.5" fill="none" stroke="{c}" stroke-width="2" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
    ),
    "search": (
        '<circle cx="11" cy="11" r="6.5" fill="none" stroke="{c}" stroke-width="2"/>'
        '<path d="M16 16l4.5 4.5" stroke="{c}" stroke-width="2" stroke-linecap="round"/>'
        '<path d="M8.5 11h5" stroke="{c}" stroke-width="2" stroke-linecap="round"/>'
    ),
    "globe": (
        '<circle cx="12" cy="12" r="8.5" fill="none" stroke="{c}" stroke-width="2"/>'
        '<path d="M3.5 12h17M12 3.5c-5.5 5-5.5 12 0 17M12 3.5c5.5 5 5.5 12 0 17" '
        'fill="none" stroke="{c}" stroke-width="1.6"/>'
    ),
    "gear": (
        '<circle cx="12" cy="12" r="3.2" fill="none" stroke="{c}" stroke-width="2"/>'
        '<path d="M12 2.8v3M12 18.2v3M2.8 12h3M18.2 12h3M5.5 5.5l2.1 2.1M16.4 16.4l2.1 2.1'
        'M18.5 5.5l-2.1 2.1M7.6 16.4l-2.1 2.1" stroke="{c}" stroke-width="2" '
        'stroke-linecap="round"/>'
    ),
    "shield": (
        '<path d="M12 2.8l7.5 3v6.1c0 4.6-3.2 7.7-7.5 9.3-4.3-1.6-7.5-4.7-7.5-9.3V5.8z" '
        'fill="none" stroke="{c}" stroke-width="2" stroke-linejoin="round"/>'
        '<path d="M8.8 12l2.3 2.3 4.1-4.5" fill="none" stroke="{c}" stroke-width="2" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
    ),
    "fingerprint": (
        '<path d="M12 2.8l7.5 3v6.1c0 4.6-3.2 7.7-7.5 9.3-4.3-1.6-7.5-4.7-7.5-9.3V5.8z" '
        'fill="none" stroke="{c}" stroke-width="1.8" stroke-linejoin="round"/>'
        '<path d="M9 16.5c.3-3.5.5-7 1.2-9.5M10.8 17c.2-3.8.4-8 1.2-10.8M12.8 17.2c.3-3.5.7-7.5 1.6-9.8M14.8 16.6c.4-2.6.8-5.2 1.5-7" '
        'fill="none" stroke="{c}" stroke-width="1.4" stroke-linecap="round"/>'
    ),
    "monitor": (
        '<rect x="3.5" y="4.5" width="17" height="12" rx="1.5" fill="none" '
        'stroke="{c}" stroke-width="2"/>'
        '<path d="M9.5 20.5h5M12 16.5v4" stroke="{c}" stroke-width="2" '
        'stroke-linecap="round"/>'
    ),
    "document": (
        '<path d="M6.5 2.8h7L19 8.3V21.2H6.5z" fill="none" stroke="{c}" '
        'stroke-width="2" stroke-linejoin="round"/>'
        '<path d="M13 3v5.5h6" fill="none" stroke="{c}" stroke-width="2" '
        'stroke-linejoin="round"/>'
    ),
    "target": (
        '<circle cx="12" cy="12" r="8.5" fill="none" stroke="{c}" stroke-width="2"/>'
        '<circle cx="12" cy="12" r="4.8" fill="none" stroke="{c}" stroke-width="2"/>'
        '<circle cx="12" cy="12" r="1.4" fill="{c}"/>'
    ),
    "clock": (
        '<circle cx="12" cy="12" r="8.5" fill="none" stroke="{c}" stroke-width="2"/>'
        '<path d="M12 7.5V12l3.2 2" fill="none" stroke="{c}" stroke-width="2" '
        'stroke-linecap="round"/>'
    ),
    "layers": (
        '<path d="M12 3.5l8.5 4.5L12 12.5 3.5 8z" fill="none" stroke="{c}" '
        'stroke-width="2" stroke-linejoin="round"/>'
        '<path d="M4.5 12.5L12 16.7l7.5-4.2M4.5 16.5L12 20.7l7.5-4.2" fill="none" '
        'stroke="{c}" stroke-width="2" stroke-linejoin="round"/>'
    ),
    "lightbulb": (
        '<path d="M9.5 18.5h5M10.5 21.5h3" stroke="{c}" stroke-width="2" '
        'stroke-linecap="round"/>'
        '<path d="M12 2.8c-3.6 0-6 2.6-6 6 0 2.1 1 3.6 2.2 4.7.8.8 1.3 1.4 1.3 2.5h5c0-1.1.5-1.7 1.3-2.5 1.2-1.1 2.2-2.6 2.2-4.7 0-3.4-2.4-6-6-6z" '
        'fill="none" stroke="{c}" stroke-width="2" stroke-linejoin="round"/>'
    ),
}

_renderers = {}


def _document(name, color=ACCENT):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" '
        f'viewBox="0 0 24 24">{_ICONS[name].format(c=color)}</svg>'
    )


def renderer(name, color=ACCENT):
    """Cached SVG renderer for an icon name (KeyError on unknown names)."""
    key = (name, color)
    if key not in _renderers:
        _renderers[key] = QSvgRenderer(QByteArray(_document(name, color).encode()))
    return _renderers[key]


def icon(name, color=ACCENT):
    """QIcon for an icon name."""
    return QIcon(pixmap(name, 24, color=color))


def pixmap(name, size, color=ACCENT):
    """Render an icon to a square pixmap of the given pixel size."""
    from PySide6.QtGui import QPainter
    rendered = QPixmap(size, size)
    rendered.fill(Qt.transparent)
    painter = QPainter(rendered)
    renderer(name, color).render(painter)
    painter.end()
    return rendered


def available():
    """Names of the bundled icons."""
    return sorted(_ICONS)
