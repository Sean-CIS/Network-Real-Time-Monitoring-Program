from PySide6.QtCore import Signal
from PySide6.QtGui import QColor
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

from src.gui import theme
from src.gui.widgets.live_chart import LiveChart
from src.gui.widgets.ring_chart import RingChart
from src.gui.widgets.stat_card import StatCard

_THREAT_COLORS = {
    "critical": QColor(255, 51, 51, 30),
    "warning": QColor(255, 176, 0, 30),
}


class PacketsView(QWidget):
    export_pcap_clicked = Signal()
    export_csv_clicked = Signal()
    generate_report_clicked = Signal()
    load_pcap_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(6, 4, 6, 4)

        # View title header
        title = QLabel("[ PACKET CAPTURE ]")
        title.setStyleSheet(theme.VIEW_TITLE)
        layout.addWidget(title)

        # Controls row 1: capture controls
        controls = QHBoxLayout()
        self._start_btn = QPushButton("Start Capture")
        self._start_btn.setStyleSheet(theme.BUTTON_PRIMARY)
        self._stop_btn = QPushButton("Stop Capture")
        self._stop_btn.setStyleSheet(theme.BUTTON_DANGER)
        self._stop_btn.setEnabled(False)

        controls.addWidget(self._start_btn)
        controls.addWidget(self._stop_btn)
        controls.addWidget(QLabel("Filter:"))
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("BPF filter (e.g. tcp port 80)")
        self._filter_input.setMinimumWidth(250)
        controls.addWidget(self._filter_input)

        self._packet_count_label = QLabel("Packets: 0")
        self._packet_count_label.setStyleSheet(f"color: {theme.GREEN_MUTED};")
        controls.addWidget(self._packet_count_label)
        controls.addStretch()
        layout.addLayout(controls)

        # Controls row 2: export buttons
        export_row = QHBoxLayout()
        self._export_pcap_btn = QPushButton("Export PCAP")
        self._export_pcap_btn.setStyleSheet(theme.BUTTON_SECONDARY)
        self._export_pcap_btn.setEnabled(False)
        self._export_pcap_btn.clicked.connect(self.export_pcap_clicked.emit)

        self._export_csv_btn = QPushButton("Export CSV")
        self._export_csv_btn.setStyleSheet(theme.BUTTON_SECONDARY)
        self._export_csv_btn.setEnabled(False)
        self._export_csv_btn.clicked.connect(self.export_csv_clicked.emit)

        self._report_btn = QPushButton("Generate Report")
        self._report_btn.setStyleSheet(theme.BUTTON_ACCENT)
        self._report_btn.setEnabled(False)
        self._report_btn.clicked.connect(self.generate_report_clicked.emit)

        self._load_pcap_btn = QPushButton("Load PCAP")
        self._load_pcap_btn.setStyleSheet(theme.BUTTON_CYAN)
        self._load_pcap_btn.clicked.connect(self.load_pcap_clicked.emit)

        export_row.addWidget(self._export_pcap_btn)
        export_row.addWidget(self._export_csv_btn)
        export_row.addWidget(self._report_btn)
        export_row.addWidget(self._load_pcap_btn)
        export_row.addStretch()
        layout.addLayout(export_row)

        # Stat cards
        cards_layout = QHBoxLayout()
        self._card_total = StatCard("Total Packets", "0")
        self._card_tcp = StatCard("TCP", "0")
        self._card_udp = StatCard("UDP", "0")
        self._card_other = StatCard("Other", "0")
        self._card_threats = StatCard("Threats", "0")
        cards_layout.addWidget(self._card_total)
        cards_layout.addWidget(self._card_tcp)
        cards_layout.addWidget(self._card_udp)
        cards_layout.addWidget(self._card_other)
        cards_layout.addWidget(self._card_threats)
        cards_layout.addStretch()
        layout.addLayout(cards_layout)

        # Top Talkers collapsible section (collapsed by default)
        self._talkers_header = QPushButton("\u25b6 Top Talkers")
        self._talkers_header.setStyleSheet(theme.COLLAPSIBLE_HEADER)
        self._talkers_header.setCursor(self._talkers_header.cursor())
        self._talkers_header.clicked.connect(self._toggle_talkers)
        layout.addWidget(self._talkers_header)

        self._talkers_table = QTableWidget()
        talker_cols = ["#", "IP", "Country", "Pkts Sent", "Pkts Recv", "Bytes Total"]
        self._talkers_table.setColumnCount(len(talker_cols))
        self._talkers_table.setHorizontalHeaderLabels(talker_cols)
        self._talkers_table.setMaximumHeight(200)
        self._talkers_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._talkers_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._talkers_table.setStyleSheet(theme.TABLE_STYLE)
        self._talkers_table.setVisible(False)  # collapsed by default
        layout.addWidget(self._talkers_table)

        # Protocol distribution (collapsible)
        self._proto_dist_header = QPushButton("\u25bc Protocol Distribution")
        self._proto_dist_header.setStyleSheet(theme.COLLAPSIBLE_HEADER)
        self._proto_dist_header.clicked.connect(self._toggle_proto_dist)
        layout.addWidget(self._proto_dist_header)

        self._proto_pie = RingChart(title="Protocol Distribution")
        self._proto_pie.setVisible(True)
        layout.addWidget(self._proto_pie)

        # Protocol rate chart (compact height)
        self._proto_chart = LiveChart(
            title="Packets per Second by Protocol",
            y_label="Packets/s",
            num_lines=3,
            line_labels=["TCP", "UDP", "Other"],
            max_points=120,
        )
        self._proto_chart.setMaximumHeight(180)
        layout.addWidget(self._proto_chart)

        # Packet table with security + process columns
        self._table = QTableWidget()
        columns = [
            "Time", "Source", "Src Country", "Destination", "Dst Country",
            "Protocol", "Process", "Length", "Info",
        ]
        self._table.setColumnCount(len(columns))
        self._table.setHorizontalHeaderLabels(columns)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setStyleSheet(theme.TABLE_STYLE)
        layout.addWidget(self._table, stretch=1)

        self._packet_count = 0
        self._threat_count = 0
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

    def _toggle_talkers(self):
        visible = not self._talkers_table.isVisible()
        self._talkers_table.setVisible(visible)
        self._talkers_header.setText(
            "\u25bc Top Talkers" if visible else "\u25b6 Top Talkers"
        )

    def _toggle_proto_dist(self):
        visible = not self._proto_pie.isVisible()
        self._proto_pie.setVisible(visible)
        self._proto_dist_header.setText(
            "\u25bc Protocol Distribution" if visible else "\u25b6 Protocol Distribution"
        )

    def update_top_talkers(self, talkers: list[dict]):
        """Update the top talkers table."""
        self._talkers_table.setRowCount(len(talkers))
        for row, t in enumerate(talkers):
            self._talkers_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            self._talkers_table.setItem(row, 1, QTableWidgetItem(t.get("ip", "")))
            self._talkers_table.setItem(row, 2, QTableWidgetItem(t.get("country", "")))
            self._talkers_table.setItem(
                row, 3, QTableWidgetItem(str(t.get("packets_sent", 0)))
            )
            self._talkers_table.setItem(
                row, 4, QTableWidgetItem(str(t.get("packets_recv", 0)))
            )
            total = t.get("bytes_total", 0)
            if total >= 1_000_000:
                display = f"{total / 1_000_000:.1f} MB"
            elif total >= 1_000:
                display = f"{total / 1_000:.1f} KB"
            else:
                display = f"{total} B"
            self._talkers_table.setItem(row, 5, QTableWidgetItem(display))

    def update_protocol_distribution(self, counts: dict[str, int]):
        """Update the protocol distribution pie chart."""
        self._proto_pie.set_data(counts)

    def set_capturing(self, capturing: bool):
        self._start_btn.setEnabled(not capturing)
        self._stop_btn.setEnabled(capturing)
        has_data = self._packet_count > 0
        self._export_pcap_btn.setEnabled(not capturing and has_data)
        self._export_csv_btn.setEnabled(not capturing and has_data)
        self._report_btn.setEnabled(not capturing and has_data)

    def add_packet(self, pkt: dict):
        self._packet_count += 1
        proto = pkt.get("protocol", "Other")
        if proto in self._proto_counts:
            self._proto_counts[proto] += 1
        else:
            self._proto_counts["Other"] += 1

        threat = pkt.get("threat_level", "")
        if threat:
            self._threat_count += 1

        self._packet_count_label.setText(f"Packets: {self._packet_count}")
        self._card_total.set_value(str(self._packet_count))
        self._card_tcp.set_value(str(self._proto_counts["TCP"]))
        self._card_udp.set_value(str(self._proto_counts["UDP"]))
        self._card_other.set_value(str(self._proto_counts["Other"]))
        self._card_threats.set_value(str(self._threat_count))

        # Add row to table
        row = self._table.rowCount()
        if row >= self._max_display:
            self._table.removeRow(0)
            row = self._table.rowCount()

        self._table.insertRow(row)

        values = [
            pkt.get("time", ""),
            pkt.get("src", ""),
            pkt.get("country_src", ""),
            pkt.get("dst", ""),
            pkt.get("country_dst", ""),
            proto,
            pkt.get("process", ""),
            str(pkt.get("length", 0)),
            pkt.get("info", ""),
        ]

        bg_color = _THREAT_COLORS.get(threat)
        for col, text in enumerate(values):
            item = QTableWidgetItem(text)
            if bg_color:
                item.setBackground(bg_color)
            if threat == "critical":
                item.setForeground(QColor(theme.RED))
            elif threat == "warning":
                item.setForeground(QColor(theme.AMBER))
            self._table.setItem(row, col, item)

        self._table.scrollToBottom()

    def update_proto_chart(self, tcp_ps: float, udp_ps: float, other_ps: float):
        self._proto_chart.add_data_point([tcp_ps, udp_ps, other_ps])

    def clear_packets(self):
        self._table.setRowCount(0)
        self._talkers_table.setRowCount(0)
        self._packet_count = 0
        self._threat_count = 0
        self._proto_counts = {"TCP": 0, "UDP": 0, "Other": 0}
        self._card_total.set_value("0")
        self._card_tcp.set_value("0")
        self._card_udp.set_value("0")
        self._card_other.set_value("0")
        self._card_threats.set_value("0")
        self._proto_chart.clear_data()
        self._proto_pie.set_data({})
