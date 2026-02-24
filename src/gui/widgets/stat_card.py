from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout

from src.gui import theme


class StatCard(QFrame):
    """A small card widget displaying a label and a value."""

    def __init__(self, title: str = "", value: str = "\u2014", parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet(
            f"""
            StatCard {{
                background-color: {theme.BG_SURFACE};
                border: 1px solid {theme.BORDER};
                border-radius: 2px;
                padding: 12px;
            }}
            """
        )
        self.setMinimumWidth(160)
        self.setMaximumHeight(100)

        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        self._title_label = QLabel(title)
        self._title_label.setStyleSheet(
            f"color: {theme.GREEN_MUTED}; font-size: 11px;"
        )
        self._title_label.setAlignment(Qt.AlignLeft)

        self._value_label = QLabel(value)
        self._value_label.setStyleSheet(
            f"color: {theme.GREEN}; font-size: 20px; font-weight: bold;"
        )
        self._value_label.setAlignment(Qt.AlignLeft)

        layout.addWidget(self._title_label)
        layout.addWidget(self._value_label)

    def set_value(self, value: str):
        self._value_label.setText(value)

    def set_title(self, title: str):
        self._title_label.setText(title)
