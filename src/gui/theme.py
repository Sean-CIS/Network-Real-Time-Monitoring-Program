"""Retro CRT terminal theme — phosphor green on dark, with scanline overlay."""

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QGraphicsDropShadowEffect, QWidget


# ── CRT Color Palette ────────────────────────────────────────────────────────

# Backgrounds
BG_DARKEST = "#050a05"       # Near-black with green tint
BG_PRIMARY = "#0a0f0a"       # Main background
BG_SURFACE = "#0d1a0d"       # Cards, panels, table headers
BG_ELEVATED = "#112211"      # Slightly elevated surfaces
BG_ALTERNATE = "#070d07"     # Table alternate row
BG_SELECTED = "#1a3a1a"      # Selected items
BG_INPUT = "#0d1a0d"         # Text input fields

# Borders
BORDER = "#1a3a1a"           # Standard borders
BORDER_DIM = "#112211"       # Dim borders

# Phosphor greens
GREEN = "#00ff41"            # Primary phosphor green — main text
GREEN_DIM = "#00cc33"        # Dimmer green — secondary text
GREEN_MUTED = "#338033"      # Muted green — labels, placeholders
GREEN_DARK = "#1a5a1a"       # Dark green — subtle accents

# Semantic colors
AMBER = "#ffb000"            # Warnings, caution
RED = "#ff3333"              # Critical, errors, danger
CYAN = "#00cccc"             # Info, teal accents
BLUE = "#0088ff"             # Informational blue

# Map / gauge specific
GREEN_GLOW = GREEN           # Semantic alias for glow color
GRID_LINE = "#0d2a0d"        # Very dark grid lines for map/gauge backgrounds

# Chart line colors
CHART_COLORS = [GREEN, AMBER, RED, CYAN, "#66ff66", "#cc8800"]

# Pie chart palette (green-dominant with accents)
PIE_COLORS = [
    QColor(GREEN), QColor(AMBER), QColor(CYAN),
    QColor("#66ff66"), QColor("#cc8800"), QColor("#00aaaa"),
    QColor("#88ff88"), QColor("#ffcc00"), QColor("#33dddd"),
    QColor("#44bb44"),
]


# ── Reusable Stylesheet Fragments ────────────────────────────────────────────

TABLE_STYLE = f"""
    QTableWidget {{
        background-color: {BG_PRIMARY}; color: {GREEN};
        gridline-color: {BORDER}; border: none;
        font-family: "Courier New", "Consolas", monospace;
    }}
    QTableWidget::item:selected {{ background-color: {BG_SELECTED}; }}
    QHeaderView::section {{
        background-color: {BG_SURFACE}; color: {GREEN};
        padding: 6px; border: 1px solid {BORDER}; font-weight: bold;
        font-family: "Courier New", "Consolas", monospace;
    }}
    QTableWidget::item:alternate {{ background-color: {BG_ALTERNATE}; }}
"""

BUTTON_PRIMARY = (
    f"QPushButton {{ background-color: {GREEN}; color: {BG_DARKEST}; "
    f"padding: 8px 16px; border-radius: 2px; font-weight: bold; "
    f'font-family: "Courier New", "Consolas", monospace; }}'
    f"QPushButton:hover {{ background-color: {GREEN_DIM}; }}"
)

BUTTON_DANGER = (
    f"QPushButton {{ background-color: {RED}; color: {BG_DARKEST}; "
    f"padding: 8px 16px; border-radius: 2px; font-weight: bold; "
    f'font-family: "Courier New", "Consolas", monospace; }}'
    f"QPushButton:hover {{ background-color: #cc2222; }}"
)

BUTTON_ACCENT = (
    f"QPushButton {{ background-color: {AMBER}; color: {BG_DARKEST}; "
    f"padding: 8px 16px; border-radius: 2px; font-weight: bold; "
    f'font-family: "Courier New", "Consolas", monospace; }}'
    f"QPushButton:hover {{ background-color: #cc8800; }}"
)

BUTTON_SECONDARY = (
    f"QPushButton {{ background-color: {BG_SURFACE}; color: {GREEN}; "
    f"padding: 8px 16px; border: 1px solid {BORDER}; border-radius: 2px; "
    f'font-weight: bold; font-family: "Courier New", "Consolas", monospace; }}'
    f"QPushButton:hover {{ background-color: {BG_SELECTED}; }}"
)

BUTTON_CYAN = (
    f"QPushButton {{ background-color: {CYAN}; color: {BG_DARKEST}; "
    f"padding: 6px 12px; border-radius: 2px; font-weight: bold; "
    f'font-family: "Courier New", "Consolas", monospace; }}'
    f"QPushButton:hover {{ background-color: #009999; }}"
)

INPUT_STYLE = (
    f"QLineEdit {{ background-color: {BG_INPUT}; color: {GREEN}; "
    f"border: 1px solid {BORDER}; border-radius: 2px; padding: 4px 8px; "
    f'font-family: "Courier New", "Consolas", monospace; }}'
)

COLLAPSIBLE_HEADER = (
    f"QPushButton {{ color: {GREEN}; font-size: 13px; font-weight: bold; "
    f"background: transparent; border: none; text-align: left; padding: 4px; "
    f'font-family: "Courier New", "Consolas", monospace; }}'
    f"QPushButton:hover {{ color: {AMBER}; }}"
)

CONTEXT_MENU = (
    f"QMenu {{ background-color: {BG_SURFACE}; color: {GREEN}; "
    f"border: 1px solid {BORDER}; "
    f'font-family: "Courier New", "Consolas", monospace; }}'
    f"QMenu::item:selected {{ background-color: {BG_SELECTED}; }}"
)


# ── Global Application Theme ─────────────────────────────────────────────────

GLOBAL_STYLESHEET = f"""
    QMainWindow {{
        background-color: {BG_PRIMARY};
    }}
    QWidget {{
        background-color: {BG_PRIMARY};
        color: {GREEN};
        font-family: "Courier New", "Consolas", monospace;
        font-size: 13px;
    }}
    QLabel {{
        color: {GREEN};
    }}
    QLineEdit {{
        background-color: {BG_INPUT};
        color: {GREEN};
        border: 1px solid {BORDER};
        border-radius: 2px;
        padding: 6px;
    }}
    QComboBox {{
        background-color: {BG_INPUT};
        color: {GREEN};
        border: 1px solid {BORDER};
        border-radius: 2px;
        padding: 6px;
    }}
    QComboBox::drop-down {{
        border: none;
    }}
    QComboBox QAbstractItemView {{
        background-color: {BG_SURFACE};
        color: {GREEN};
        selection-background-color: {BG_SELECTED};
    }}
    QScrollBar:vertical {{
        background: {BG_PRIMARY};
        width: 10px;
    }}
    QScrollBar::handle:vertical {{
        background: {BORDER};
        border-radius: 5px;
    }}
    QScrollBar:horizontal {{
        background: {BG_PRIMARY};
        height: 10px;
    }}
    QScrollBar::handle:horizontal {{
        background: {BORDER};
        border-radius: 5px;
    }}
"""

TAB_STYLESHEET = f"""
    QTabWidget::pane {{
        border: 1px solid {BORDER};
        background-color: {BG_PRIMARY};
    }}
    QTabBar::tab {{
        background-color: {BG_SURFACE};
        color: {GREEN_MUTED};
        padding: 10px 20px;
        margin-right: 2px;
        border-top-left-radius: 2px;
        border-top-right-radius: 2px;
        border: 1px solid {BORDER};
        border-bottom: none;
        font-family: "Courier New", "Consolas", monospace;
        font-weight: bold;
    }}
    QTabBar::tab:selected {{
        background-color: {BG_SELECTED};
        color: {GREEN};
    }}
    QTabBar::tab:hover {{
        background-color: {BG_ELEVATED};
        color: {GREEN_DIM};
    }}
"""

STATUS_BAR_STYLE = (
    f"QStatusBar {{ background-color: {BG_SURFACE}; color: {GREEN}; "
    f"border-top: 1px solid {BORDER}; padding: 2px; }}"
    f"QStatusBar::item {{ border: none; }}"
)


# ── Glow Effect Utilities ─────────────────────────────────────────────────────


def apply_glow(widget, color=GREEN, blur_radius=15, offset=(0, 0)):
    """Apply a static phosphor glow drop-shadow to any QWidget."""
    effect = QGraphicsDropShadowEffect(widget)
    effect.setColor(QColor(color))
    effect.setBlurRadius(blur_radius)
    effect.setOffset(offset[0], offset[1])
    widget.setGraphicsEffect(effect)
    return effect


class PulsingGlow(QPropertyAnimation):
    """Animate the blur radius of a QGraphicsDropShadowEffect to pulse."""

    def __init__(self, effect: QGraphicsDropShadowEffect,
                 min_blur=5, max_blur=25, duration_ms=1200, parent=None):
        super().__init__(effect, b"blurRadius", parent)
        self.setStartValue(float(min_blur))
        self.setEndValue(float(max_blur))
        self.setDuration(duration_ms)
        self.setEasingCurve(QEasingCurve.InOutSine)
        self.setLoopCount(-1)


# ── CRT Scanline Overlay Widget ──────────────────────────────────────────────

class ScanlineOverlay(QWidget):
    """Semi-transparent overlay that draws CRT-style horizontal scanlines."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setStyleSheet("background: transparent;")
        self._line_spacing = 3
        self._line_opacity = 18  # 0-255, very subtle

    def paintEvent(self, event):
        painter = QPainter(self)
        pen = QPen(QColor(0, 0, 0, self._line_opacity))
        pen.setWidth(1)
        painter.setPen(pen)

        h = self.height()
        w = self.width()
        y = 0
        while y < h:
            painter.drawLine(0, y, w, y)
            y += self._line_spacing
        painter.end()
