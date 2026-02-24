from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.gui.widgets.live_chart import LiveChart
from src.gui.widgets.stat_card import StatCard


class PacketsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Controls row
        controls = QHBoxLayout()
        self._start_btn = QPushButton("Start Capture")
        self._start_btn.setStyleSheet(
            "QPushButton { background-color: #a6e3a1; color: #1e1e2e; "
            "padding: 8px 16px; border-radius: 4px; font-weight: bold; }"
        )
        self._stop_btn = QPushButton("Stop Capture")
        self._stop_btn.setStyleSheet(
            "QPushButton { background-color: #f38ba8; color: #1e1e2e; "
            "padding: 8px 16px; border-radius: 4px; font-weight: bold; }"
        )
        self._stop_btn.setEnabled(False)

        controls.addWidget(self._start_btn)
        controls.addWidget(self._stop_btn)
        controls.addWidget(QLabel("Filter:"))
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("BPF filter (e.g. tcp port 80)")
        self._filter_input.setMinimumWidth(250)
        controls.addWidget(self._filter_input)

        self._packet_count_label = QLabel("Packets: 0")
        self._packet_count_label.setStyleSheet("color: #a6adc8;")
        controls.addWidget(self._packet_count_label)
        controls.addStretch()
        layout.addLayout(controls)

        # Stat cards
        cards_layout = QHBoxLayout()
        self._card_total = StatCard("Total Packets", "0")
        self._card_tcp = StatCard("TCP", "0")
        self._card_udp = StatCard("UDP", "0")
        self._card_other = StatCard("Other", "0")
        cards_layout.addWidget(self._card_total)
        cards_layout.addWidget(self._card_tcp)
        cards_layout.addWidget(self._card_udp)
        cards_layout.addWidget(self._card_other)
        cards_layout.addStretch()
        layout.addLayout(cards_layout)

        # Protocol distribution chart
        self._proto_chart = LiveChart(
            title="Packets per Second by Protocol",
            y_label="Packets/s",
            num_lines=3,
            line_labels=["TCP", "UDP", "Other"],
            max_points=120,
        )
        layout.addWidget(self._proto_chart)

        # Packet table
        self._table = QTableWidget()
        columns = ["Time", "Source", "Destination", "Protocol", "Length", "Info"]
        self._table.setColumnCount(len(columns))
        self._table.setHorizontalHeaderLabels(columns)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setStyleSheet(
            """
            QTableWidget {
                background-color: #1e1e2e; color: #cdd6f4;
                gridline-color: #45475a; border: none;
            }
            QTableWidget::item:selected { background-color: #45475a; }
            QHeaderView::section {
                background-color: #313244; color: #cdd6f4;
                padding: 6px; border: 1px solid #45475a; font-weight: bold;
            }
            QTableWidget::item:alternate { background-color: #181825; }
            """
        )
        layout.addWidget(self._table, stretch=1)

        self._packet_count = 0
        self._proto_counts = {"TCP": 0, "UDP": 0, "Other": 0}
        self._max_display = 1000

    @property
    def start_button(self) -> QPushButton:
        return self._start_btn

    @property
    def stop_button(self) -> QPushButton:
        return self._stop_btn

    @property
    def filter_text(self) -> str:
        return self._filter_input.text().strip()

    def set_capturing(self, capturing: bool):
        self._start_btn.setEnabled(not capturing)
        self._stop_btn.setEnabled(capturing)

    def add_packet(self, pkt: dict):
        self._packet_count += 1
        proto = pkt.get("protocol", "Other")
        if proto in self._proto_counts:
            self._proto_counts[proto] += 1
        else:
            self._proto_counts["Other"] += 1

        self._packet_count_label.setText(f"Packets: {self._packet_count}")
        self._card_total.set_value(str(self._packet_count))
        self._card_tcp.set_value(str(self._proto_counts["TCP"]))
        self._card_udp.set_value(str(self._proto_counts["UDP"]))
        self._card_other.set_value(str(self._proto_counts["Other"]))

        # Add row to table
        row = self._table.rowCount()
        if row >= self._max_display:
            self._table.removeRow(0)
            row = self._table.rowCount()

        self._table.insertRow(row)
        self._table.setItem(row, 0, QTableWidgetItem(pkt.get("time", "")))
        self._table.setItem(row, 1, QTableWidgetItem(pkt.get("src", "")))
        self._table.setItem(row, 2, QTableWidgetItem(pkt.get("dst", "")))
        self._table.setItem(row, 3, QTableWidgetItem(proto))
        self._table.setItem(row, 4, QTableWidgetItem(str(pkt.get("length", 0))))
        self._table.setItem(row, 5, QTableWidgetItem(pkt.get("info", "")))
        self._table.scrollToBottom()

    def update_proto_chart(self, tcp_ps: float, udp_ps: float, other_ps: float):
        self._proto_chart.add_data_point([tcp_ps, udp_ps, other_ps])

    def clear_packets(self):
        self._table.setRowCount(0)
        self._packet_count = 0
        self._proto_counts = {"TCP": 0, "UDP": 0, "Other": 0}
        self._card_total.set_value("0")
        self._card_tcp.set_value("0")
        self._card_udp.set_value("0")
        self._card_other.set_value("0")
        self._proto_chart.clear_data()
