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
    "chart": (
        '<path d="M4 19h16M7 16V11M12 16V6M17 16v-4" stroke="{c}" stroke-width="2" '
        'stroke-linecap="round"/>'
    ),
    "grid": (
        '<rect x="4" y="4" width="6.5" height="6.5" rx="1.5" fill="none" stroke="{c}" stroke-width="2"/>'
        '<rect x="13.5" y="4" width="6.5" height="6.5" rx="1.5" fill="none" stroke="{c}" stroke-width="2"/>'
        '<rect x="4" y="13.5" width="6.5" height="6.5" rx="1.5" fill="none" stroke="{c}" stroke-width="2"/>'
        '<rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.5" fill="none" stroke="{c}" stroke-width="2"/>'
    ),
    "window": (
        '<rect x="3.5" y="4.5" width="17" height="15" rx="2" fill="none" stroke="{c}" stroke-width="2"/>'
        '<path d="M3.5 9h17M6.5 6.8h.01M9 6.8h.01" stroke="{c}" stroke-width="2" stroke-linecap="round"/>'
    ),
    "shield_check": (
        '<path d="M12 2.8l7.5 3v6.1c0 4.6-3.2 7.7-7.5 9.3-4.3-1.6-7.5-4.7-7.5-9.3V5.8z" '
        'fill="none" stroke="{c}" stroke-width="2" stroke-linejoin="round"/>'
        '<path d="M8.8 12l2.3 2.3 4.1-4.5" fill="none" stroke="{c}" stroke-width="2" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
    ),
    "laptop_hero": "",
}

_renderers = {}


def _document(name, color=ACCENT):
    if name == "laptop_hero":
        return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 130" width="240" height="130">
  <defs>
    <linearGradient id="screenGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#081726"/>
      <stop offset="100%" stop-color="#040a12"/>
    </linearGradient>
    <linearGradient id="cyanGlow" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00f2fe"/>
      <stop offset="100%" stop-color="{color}"/>
    </linearGradient>
  </defs>
  <path d="M10 110 L230 110 M30 120 L210 120" stroke="#163248" stroke-width="1" stroke-opacity="0.6"/>
  <polygon points="50,96 190,96 210,108 30,108" fill="#0e1f30" stroke="#224b6b" stroke-width="1.5"/>
  <polygon points="85,99 155,99 150,105 90,105" fill="#162f47"/>
  <polygon points="60,20 180,20 186,96 54,96" fill="url(#screenGrad)" stroke="{color}" stroke-width="2"/>
  <path d="M120 38 l20 8 v18 c0 14 -10 23 -20 28 c-10 -5 -20 -14 -20 -28 v-18 z" fill="#092434" stroke="url(#cyanGlow)" stroke-width="2"/>
  <path d="M113 72 c.5 -6 1 -12 2.2 -16 M117 73 c.4 -7 .8 -14 2 -18 M123 74 c.5 -6 1.2 -13 2.5 -17" fill="none" stroke="{color}" stroke-width="1.5" stroke-linecap="round"/>
  <line x1="42" y1="35" x2="60" y2="45" stroke="{color}" stroke-width="1" stroke-dasharray="2,2" stroke-opacity="0.7"/>
  <circle cx="42" cy="35" r="12" fill="#0c2132" stroke="{color}" stroke-width="1.5"/>
  <circle cx="42" cy="32" r="3.5" fill="none" stroke="{color}" stroke-width="1.2"/>
  <path d="M36 42 c0 -3 2.5 -4.5 6 -4.5 s6 1.5 6 4.5" fill="none" stroke="{color}" stroke-width="1.2"/>
  <line x1="198" y1="35" x2="180" y2="45" stroke="{color}" stroke-width="1" stroke-dasharray="2,2" stroke-opacity="0.7"/>
  <circle cx="198" cy="35" r="12" fill="#0c2132" stroke="{color}" stroke-width="1.5"/>
  <path d="M192 32 h4 l2 2 h6 v7 h-12 z" fill="none" stroke="{color}" stroke-width="1.2"/>
  <line x1="32" y1="80" x2="54" y2="80" stroke="{color}" stroke-width="1" stroke-dasharray="2,2" stroke-opacity="0.7"/>
  <circle cx="32" cy="80" r="12" fill="#0c2132" stroke="{color}" stroke-width="1.5"/>
  <ellipse cx="32" cy="76" rx="6" ry="2" fill="none" stroke="{color}" stroke-width="1"/>
  <path d="M26 76 v4 c0 1.1 2.7 2 6 2 s6 -.9 6 -2 v-4 M26 80 v4 c0 1.1 2.7 2 6 2 s6 -.9 6 -2 v-4" fill="none" stroke="{color}" stroke-width="1"/>
  <line x1="208" y1="78" x2="186" y2="78" stroke="{color}" stroke-width="1" stroke-dasharray="2,2" stroke-opacity="0.7"/>
  <circle cx="208" cy="78" r="12" fill="#0c2132" stroke="{color}" stroke-width="1.5"/>
  <path d="M202 73 h7 l4 4 v8 h-11 z" fill="none" stroke="{color}" stroke-width="1.2"/>
</svg>'''
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
    """Render an icon to a square or sized pixmap."""
    from PySide6.QtGui import QPainter
    w, h = (size, size) if isinstance(size, int) else size
    rendered = QPixmap(w, h)
    rendered.fill(Qt.transparent)
    painter = QPainter(rendered)
    renderer(name, color).render(painter)
    painter.end()
    return rendered


def available():
    """Names of the bundled icons."""
    return sorted(_ICONS)
