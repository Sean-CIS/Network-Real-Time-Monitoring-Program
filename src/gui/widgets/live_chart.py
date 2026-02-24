import numpy as np
import pyqtgraph as pg
from PySide6.QtWidgets import QVBoxLayout, QWidget

from src.gui import theme


class LiveChart(QWidget):
    """A reusable real-time line chart widget using PyQtGraph."""

    def __init__(self, title: str = "", y_label: str = "", max_points: int = 300,
                 num_lines: int = 1, line_labels: list[str] | None = None,
                 parent=None):
        super().__init__(parent)
        self._max_points = max_points
        self._num_lines = num_lines

        pg.setConfigOptions(antialias=True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._plot_widget = pg.PlotWidget()
        self._plot_widget.setBackground(theme.BG_PRIMARY)
        self._plot_widget.showGrid(x=True, y=True, alpha=0.15)
        self._plot_widget.setTitle(title, color=theme.GREEN, size="12pt")
        self._plot_widget.setLabel("left", y_label, color=theme.GREEN_DIM)
        self._plot_widget.setLabel("bottom", "Time (s)", color=theme.GREEN_DIM)
        self._plot_widget.setLimits(yMin=0)

        # Style axes
        for axis_name in ("left", "bottom"):
            axis = self._plot_widget.getAxis(axis_name)
            axis.setPen(pg.mkPen(color=theme.BORDER, width=1))
            axis.setTextPen(pg.mkPen(color=theme.GREEN_MUTED))

        colors = theme.CHART_COLORS
        self._lines: list[pg.PlotDataItem] = []
        self._data: list[np.ndarray] = []
        self._x_data = np.array([])

        labels = line_labels or [f"Line {i}" for i in range(num_lines)]
        legend = self._plot_widget.addLegend(offset=(10, 10))
        legend.setLabelTextColor(theme.GREEN_DIM)

        for i in range(num_lines):
            color = colors[i % len(colors)]
            pen = pg.mkPen(color=color, width=2)
            line = self._plot_widget.plot([], [], pen=pen, name=labels[i],
                                          connect="finite")
            self._lines.append(line)
            self._data.append(np.array([]))

        layout.addWidget(self._plot_widget)

    def add_data_point(self, values: list[float]):
        """Add a single data point across all lines."""
        if len(self._x_data) == 0:
            self._x_data = np.array([0.0])
        else:
            self._x_data = np.append(self._x_data, self._x_data[-1] + 1.0)

        for i, val in enumerate(values):
            if i < self._num_lines:
                self._data[i] = np.append(self._data[i], val)

        # Trim to max_points
        if len(self._x_data) > self._max_points:
            trim = len(self._x_data) - self._max_points
            self._x_data = self._x_data[trim:]
            for i in range(self._num_lines):
                self._data[i] = self._data[i][trim:]

        # Update plot lines in-place
        for i in range(self._num_lines):
            if i < len(values):
                self._lines[i].setData(self._x_data, self._data[i])

    def set_y_label(self, label: str):
        """Update the Y-axis label dynamically."""
        self._plot_widget.setLabel("left", label, color=theme.GREEN_DIM)

    def clear_data(self):
        self._x_data = np.array([])
        for i in range(self._num_lines):
            self._data[i] = np.array([])
            self._lines[i].setData([], [])
