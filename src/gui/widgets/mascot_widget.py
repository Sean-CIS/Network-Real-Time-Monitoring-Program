"""Anime-style cyberpunk hacker girl mascot widget drawn entirely with QPainter."""

import math
import random
from PySide6.QtCore import (
    Qt, QRectF, QPointF, QTimer, Property, QPropertyAnimation,
    QEasingCurve, QSize,
)
from PySide6.QtGui import (
    QPainter, QColor, QPen, QFont, QBrush, QRadialGradient,
    QLinearGradient, QPainterPath,
)
from PySide6.QtWidgets import QWidget


class _RainDrop:
    """A single character for the matrix-rain effect during SCANNING state."""

    __slots__ = ("x", "y", "char", "speed", "opacity")

    def __init__(self, width: int):
        self.x = random.randint(0, max(width, 1))
        self.y = random.randint(-220, 0)
        self.char = random.choice(
            "abcdefghijklmnopqrstuvwxyz0123456789@#$%&*{}[]<>/\\=+"
        )
        self.speed = random.uniform(1.5, 4.0)
        self.opacity = random.uniform(0.3, 0.9)

    def advance(self, height: int, width: int):
        self.y += self.speed
        if self.y > height:
            self.y = random.randint(-40, 0)
            self.x = random.randint(0, max(width, 1))
            self.char = random.choice(
                "abcdefghijklmnopqrstuvwxyz0123456789@#$%&*{}[]<>/\\=+"
            )
            self.speed = random.uniform(1.5, 4.0)
            self.opacity = random.uniform(0.3, 0.9)


class _Sparkle:
    """A floating sparkle dot for the SAFE state."""

    __slots__ = ("x", "y", "phase", "speed", "size")

    def __init__(self, width: int, height: int):
        self.x = random.randint(10, max(width - 10, 11))
        self.y = random.randint(int(height * 0.3), height)
        self.phase = random.uniform(0, 2 * math.pi)
        self.speed = random.uniform(0.3, 1.0)
        self.size = random.uniform(1.5, 3.5)

    def advance(self, width: int, height: int):
        self.y -= self.speed
        self.phase += 0.08
        if self.y < 0:
            self.y = random.randint(int(height * 0.6), height)
            self.x = random.randint(10, max(width - 10, 11))
            self.phase = random.uniform(0, 2 * math.pi)


# ---------------------------------------------------------------------------
# Messages per state
# ---------------------------------------------------------------------------
_MESSAGES: dict[str, list[str]] = {
    "idle": [
        "Monitoring network...",
        "All quiet on the wire~",
        "Watching {n} devices",
    ],
    "alert": [
        "Threat detected!",
        "Suspicious activity!",
    ],
    "scanning": [
        "Scanning network...",
        "Checking ports...",
    ],
    "safe": [
        "All clear~",
        "Network is clean \u2713",
    ],
}


class MascotWidget(QWidget):
    """QPainter-drawn anime cyberpunk hacker girl with animated states.

    States: ``idle``, ``alert``, ``scanning``, ``safe``.
    """

    # Expose _breath_offset as a Qt property for QPropertyAnimation
    def _get_breath_offset(self) -> float:
        return self._breath_offset

    def _set_breath_offset(self, v: float):
        self._breath_offset = v
        self.update()

    breathOffset = Property(float, _get_breath_offset, _set_breath_offset)

    # Expose _alert_glow as a Qt property for QPropertyAnimation
    def _get_alert_glow(self) -> float:
        return self._alert_glow

    def _set_alert_glow(self, v: float):
        self._alert_glow = v
        self.update()

    alertGlow = Property(float, _get_alert_glow, _set_alert_glow)

    # ------------------------------------------------------------------
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(150, 220)

        # State
        self._state: str = "idle"
        self._device_count: int = 0

        # Animation properties
        self._breath_offset: float = 0.0
        self._alert_glow: float = 0.0

        # Blinking
        self._blink_visible: bool = False
        self._blink_timer = QTimer(self)
        self._blink_timer.setInterval(5000)
        self._blink_timer.timeout.connect(self._start_blink)
        self._blink_timer.start()

        self._blink_end_timer = QTimer(self)
        self._blink_end_timer.setSingleShot(True)
        self._blink_end_timer.setInterval(150)
        self._blink_end_timer.timeout.connect(self._end_blink)

        # Breathing animation
        self._breath_anim = QPropertyAnimation(self, b"breathOffset", self)
        self._breath_anim.setDuration(3000)
        self._breath_anim.setStartValue(0.0)
        self._breath_anim.setKeyValueAt(0.5, -2.0)
        self._breath_anim.setEndValue(0.0)
        self._breath_anim.setEasingCurve(QEasingCurve.InOutSine)
        self._breath_anim.setLoopCount(-1)
        self._breath_anim.start()

        # Alert glow animation
        self._alert_anim = QPropertyAnimation(self, b"alertGlow", self)
        self._alert_anim.setDuration(1200)
        self._alert_anim.setStartValue(0.05)
        self._alert_anim.setKeyValueAt(0.5, 0.35)
        self._alert_anim.setEndValue(0.05)
        self._alert_anim.setEasingCurve(QEasingCurve.InOutSine)
        self._alert_anim.setLoopCount(-1)

        # Scanning rain
        self._rain_drops: list[_RainDrop] = [_RainDrop(self.width()) for _ in range(15)]
        self._rain_timer = QTimer(self)
        self._rain_timer.setInterval(33)  # ~30 fps
        self._rain_timer.timeout.connect(self._advance_rain)

        # Safe sparkles
        self._sparkles: list[_Sparkle] = [
            _Sparkle(self.width(), self.height()) for _ in range(12)
        ]
        self._sparkle_timer = QTimer(self)
        self._sparkle_timer.setInterval(33)
        self._sparkle_timer.timeout.connect(self._advance_sparkles)

        # Speech bubble typewriter
        self._bubble_text: str = ""
        self._bubble_display: str = ""
        self._bubble_index: int = 0
        self._typewriter_timer = QTimer(self)
        self._typewriter_timer.setInterval(30)
        self._typewriter_timer.timeout.connect(self._typewriter_tick)

        # Message rotation
        self._msg_cycle_timer = QTimer(self)
        self._msg_cycle_timer.setInterval(8000)
        self._msg_cycle_timer.timeout.connect(self._next_message)
        self._msg_cycle_timer.start()

        self._message_index: int = 0

        # Kick off initial message
        self._next_message()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def set_state(self, state: str):
        """Set the mascot state: ``idle``, ``alert``, ``scanning``, ``safe``."""
        state = state.lower()
        if state not in _MESSAGES:
            return
        if state == self._state:
            return
        self._state = state
        self._message_index = 0

        # Stop state-specific animations
        self._alert_anim.stop()
        self._rain_timer.stop()
        self._sparkle_timer.stop()
        self._alert_glow = 0.0

        if state == "alert":
            self._alert_anim.start()
        elif state == "scanning":
            self._rain_drops = [_RainDrop(self.width()) for _ in range(15)]
            self._rain_timer.start()
        elif state == "safe":
            self._sparkles = [
                _Sparkle(self.width(), self.height()) for _ in range(12)
            ]
            self._sparkle_timer.start()

        # Immediately show a contextual message
        self._next_message()
        self.update()

    def set_device_count(self, count: int):
        """Update the device count used in the *Watching {n} devices* message."""
        self._device_count = count

    # ------------------------------------------------------------------
    # Internal timers / helpers
    # ------------------------------------------------------------------
    def _start_blink(self):
        self._blink_visible = True
        self._blink_end_timer.start()
        self.update()

    def _end_blink(self):
        self._blink_visible = False
        self.update()

    def _advance_rain(self):
        w, h = self.width(), self.height()
        for drop in self._rain_drops:
            drop.advance(h, w)
        self.update()

    def _advance_sparkles(self):
        w, h = self.width(), self.height()
        for s in self._sparkles:
            s.advance(w, h)
        self.update()

    def _next_message(self):
        msgs = _MESSAGES.get(self._state, _MESSAGES["idle"])
        text = msgs[self._message_index % len(msgs)]
        self._message_index += 1
        # Substitute device count
        text = text.replace("{n}", str(self._device_count))
        self._bubble_text = text
        self._bubble_display = ""
        self._bubble_index = 0
        self._typewriter_timer.start()

    def _typewriter_tick(self):
        if self._bubble_index < len(self._bubble_text):
            self._bubble_index += 1
            self._bubble_display = self._bubble_text[: self._bubble_index]
            self.update()
        else:
            self._typewriter_timer.stop()

    # ------------------------------------------------------------------
    # Painting
    # ------------------------------------------------------------------
    def paintEvent(self, event):  # noqa: C901 (complex but purely visual)
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setRenderHint(QPainter.SmoothPixmapTransform)

        w = self.width()
        h = self.height()

        # Vertical breathing offset applied globally
        by = self._breath_offset

        # --- Background glow ---------------------------------------------------
        self._paint_bg_glow(p, w, h)

        # --- Scanning rain (behind character) ----------------------------------
        if self._state == "scanning":
            self._paint_rain(p)

        # --- Safe sparkles (behind character) ----------------------------------
        if self._state == "safe":
            self._paint_sparkles(p)

        # --- Alert red glow behind character -----------------------------------
        if self._state == "alert" and self._alert_glow > 0:
            glow_c = QColor(255, 40, 40, int(self._alert_glow * 255))
            grad = QRadialGradient(QPointF(w / 2, 120 + by), 80)
            grad.setColorAt(0, glow_c)
            grad.setColorAt(1, QColor(255, 40, 40, 0))
            p.setBrush(QBrush(grad))
            p.setPen(Qt.NoPen)
            p.drawEllipse(QPointF(w / 2, 120 + by), 80, 80)

        # --- Character drawing (centered at ~75, offset by breathing) ----------
        cx = w / 2  # horizontal center

        self._paint_body(p, cx, by)
        self._paint_laptop(p, cx, by)
        self._paint_hair_back(p, cx, by)
        self._paint_head(p, cx, by)
        self._paint_hair_front(p, cx, by)

        # --- Speech bubble (not affected by breathing) -------------------------
        self._paint_bubble(p, cx)

        p.end()

    # ---- Sub-painters ---------------------------------------------------------

    def _paint_bg_glow(self, p: QPainter, w: int, h: int):
        """Subtle green circular glow at 10% opacity behind the character."""
        c = QColor(0, 255, 65, 25)  # ~10 %
        grad = QRadialGradient(QPointF(w / 2, h / 2 + 10), 100)
        grad.setColorAt(0, c)
        grad.setColorAt(1, QColor(0, 255, 65, 0))
        p.setBrush(QBrush(grad))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QPointF(w / 2, h / 2 + 10), 100, 100)

    # ---- Body -----------------------------------------------------------------

    def _paint_body(self, p: QPainter, cx: float, by: float):
        """Dark hoodie as rounded trapezoid."""
        hoodie = QColor("#1a1a2e")

        path = QPainterPath()
        # Shoulders
        top_y = 108 + by
        bot_y = 185 + by
        shoulder_half = 32
        hip_half = 42

        path.moveTo(cx - shoulder_half, top_y)
        # Left shoulder curve
        path.cubicTo(
            cx - shoulder_half - 10, top_y,
            cx - hip_half - 4, top_y + 20,
            cx - hip_half, bot_y,
        )
        # Bottom
        path.lineTo(cx + hip_half, bot_y)
        # Right side up
        path.cubicTo(
            cx + hip_half + 4, top_y + 20,
            cx + shoulder_half + 10, top_y,
            cx + shoulder_half, top_y,
        )
        path.closeSubpath()

        p.setBrush(QBrush(hoodie))
        p.setPen(Qt.NoPen)
        p.drawPath(path)

        # Hoodie collar (small V shape)
        p.setPen(QPen(QColor("#2d2d4a"), 1.5))
        p.drawLine(QPointF(cx - 8, 108 + by), QPointF(cx, 116 + by))
        p.drawLine(QPointF(cx, 116 + by), QPointF(cx + 8, 108 + by))

        # Terminal prompt "> _" on chest
        font = QFont("Consolas", 9, QFont.Bold)
        p.setFont(font)
        p.setPen(QColor("#00ff41"))
        p.drawText(QRectF(cx - 20, 130 + by, 40, 16), Qt.AlignCenter, "> _")

    # ---- Laptop ---------------------------------------------------------------

    def _paint_laptop(self, p: QPainter, cx: float, by: float):
        """Small laptop rectangle in front of the character."""
        # Laptop base
        lx = cx - 22
        ly = 172 + by
        lw = 44
        lh = 12
        p.setBrush(QBrush(QColor("#1a1a2e")))
        p.setPen(QPen(QColor("#333355"), 1))
        p.drawRoundedRect(QRectF(lx, ly, lw, lh), 2, 2)

        # Screen (angled upward from back edge)
        screen_path = QPainterPath()
        screen_path.moveTo(lx + 2, ly)
        screen_path.lineTo(lx + 6, ly - 14)
        screen_path.lineTo(lx + lw - 6, ly - 14)
        screen_path.lineTo(lx + lw - 2, ly)
        screen_path.closeSubpath()

        p.setBrush(QBrush(QColor("#0d0d1a")))
        p.setPen(QPen(QColor("#333355"), 1))
        p.drawPath(screen_path)

        # Green glow on screen edge
        glow_pen = QPen(QColor(0, 255, 65, 120), 1.5)
        p.setPen(glow_pen)
        p.drawLine(QPointF(lx + 8, ly - 12), QPointF(lx + lw - 8, ly - 12))

    # ---- Hair (back layer) ----------------------------------------------------

    def _paint_hair_back(self, p: QPainter, cx: float, by: float):
        """Long flowing hair drawn behind the head (back layer)."""
        hair_color = QColor("#3b1d6e")  # dark purple
        hair_color2 = QColor("#1a0a3e")  # darker

        p.setPen(Qt.NoPen)

        # Large back-hair mass
        grad = QLinearGradient(QPointF(cx, 60 + by), QPointF(cx, 160 + by))
        grad.setColorAt(0, hair_color)
        grad.setColorAt(1, hair_color2)
        p.setBrush(QBrush(grad))

        path = QPainterPath()
        path.moveTo(cx - 28, 68 + by)
        path.cubicTo(cx - 38, 80 + by, cx - 42, 120 + by, cx - 36, 150 + by)
        path.cubicTo(cx - 34, 158 + by, cx - 28, 160 + by, cx - 22, 155 + by)
        path.lineTo(cx - 18, 110 + by)
        path.closeSubpath()
        p.drawPath(path)

        path2 = QPainterPath()
        path2.moveTo(cx + 28, 68 + by)
        path2.cubicTo(cx + 38, 80 + by, cx + 42, 120 + by, cx + 36, 150 + by)
        path2.cubicTo(cx + 34, 158 + by, cx + 28, 160 + by, cx + 22, 155 + by)
        path2.lineTo(cx + 18, 110 + by)
        path2.closeSubpath()
        p.drawPath(path2)

        # Extra flowing strands at the back
        strand_pen = QPen(hair_color, 2.5, Qt.SolidLine, Qt.RoundCap)
        p.setPen(strand_pen)
        p.setBrush(Qt.NoBrush)

        for dx, ctrl_x, end_y in [(-30, -44, 145), (-25, -40, 140),
                                    (30, 44, 145), (25, 40, 140)]:
            strand = QPainterPath()
            strand.moveTo(cx + dx * 0.8, 72 + by)
            strand.cubicTo(
                cx + dx, 95 + by,
                cx + ctrl_x, 120 + by,
                cx + dx * 1.1, end_y + by,
            )
            p.drawPath(strand)

    # ---- Head -----------------------------------------------------------------

    def _paint_head(self, p: QPainter, cx: float, by: float):
        """Head with skin gradient, eyes, nose, mouth."""
        head_cx = cx
        head_cy = 78 + by
        head_rx = 24
        head_ry = 26

        # Skin gradient
        skin_grad = QRadialGradient(QPointF(head_cx - 4, head_cy - 6), 36)
        skin_grad.setColorAt(0, QColor("#ffe0c2"))
        skin_grad.setColorAt(0.7, QColor("#f5c4a1"))
        skin_grad.setColorAt(1, QColor("#e6a97a"))
        p.setBrush(QBrush(skin_grad))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QPointF(head_cx, head_cy), head_rx, head_ry)

        # --- Eyes ---
        eye_y = 80 + by
        left_eye_x = cx - 10
        right_eye_x = cx + 10
        eye_r = 5.5  # large anime eyes

        if self._blink_visible and self._state == "idle":
            # Blink: thin horizontal lines
            p.setPen(QPen(QColor("#222222"), 1.5, Qt.SolidLine, Qt.RoundCap))
            p.drawLine(QPointF(left_eye_x - 4, eye_y), QPointF(left_eye_x + 4, eye_y))
            p.drawLine(QPointF(right_eye_x - 4, eye_y), QPointF(right_eye_x + 4, eye_y))
        else:
            # Eye colour depends on state
            if self._state == "alert":
                iris_color = QColor("#ff2020")
            else:
                iris_color = QColor("#00ff41")

            for ex in (left_eye_x, right_eye_x):
                # White of eye
                p.setBrush(QBrush(QColor("#ffffff")))
                p.setPen(Qt.NoPen)
                p.drawEllipse(QPointF(ex, eye_y), eye_r, eye_r)

                # Iris
                p.setBrush(QBrush(iris_color))
                p.drawEllipse(QPointF(ex, eye_y), eye_r - 1.5, eye_r - 1.5)

                # Pupil
                p.setBrush(QBrush(QColor("#000000")))
                p.drawEllipse(QPointF(ex, eye_y), 2.0, 2.0)

                # Anime highlight dot (top-right of each eye)
                p.setBrush(QBrush(QColor("#ffffff")))
                p.drawEllipse(QPointF(ex + 1.5, eye_y - 2.0), 1.3, 1.3)

        # Nose — single small line
        p.setPen(QPen(QColor("#d4a07a"), 1.2, Qt.SolidLine, Qt.RoundCap))
        p.drawLine(QPointF(cx, 85 + by), QPointF(cx - 1.5, 88 + by))

        # Mouth
        if self._state == "safe":
            # Small smile arc
            smile = QPainterPath()
            smile.moveTo(cx - 5, 93 + by)
            smile.cubicTo(cx - 3, 96 + by, cx + 3, 96 + by, cx + 5, 93 + by)
            p.setPen(QPen(QColor("#c4846a"), 1.3, Qt.SolidLine, Qt.RoundCap))
            p.setBrush(Qt.NoBrush)
            p.drawPath(smile)
        else:
            # Small neutral mouth line
            p.setPen(QPen(QColor("#c4846a"), 1.2, Qt.SolidLine, Qt.RoundCap))
            p.drawLine(QPointF(cx - 4, 93 + by), QPointF(cx + 4, 93 + by))

    # ---- Hair (front/fringe layer) -------------------------------------------

    def _paint_hair_front(self, p: QPainter, cx: float, by: float):
        """Fringe strands over the forehead and side locks."""
        hair_color = QColor("#4b2d8e")  # slightly lighter purple for front
        p.setPen(Qt.NoPen)

        # Top hair cap
        cap = QPainterPath()
        cap.moveTo(cx - 28, 72 + by)
        cap.cubicTo(cx - 30, 52 + by, cx + 30, 52 + by, cx + 28, 72 + by)
        cap.cubicTo(cx + 20, 62 + by, cx - 20, 62 + by, cx - 28, 72 + by)
        cap.closeSubpath()

        cap_grad = QLinearGradient(QPointF(cx, 50 + by), QPointF(cx, 75 + by))
        cap_grad.setColorAt(0, QColor("#5c35a8"))
        cap_grad.setColorAt(1, hair_color)
        p.setBrush(QBrush(cap_grad))
        p.drawPath(cap)

        # Individual fringe strands
        strand_pen = QPen(hair_color, 3.0, Qt.SolidLine, Qt.RoundCap)
        p.setPen(strand_pen)
        p.setBrush(Qt.NoBrush)

        # Left fringe
        s = QPainterPath()
        s.moveTo(cx - 14, 56 + by)
        s.cubicTo(cx - 20, 62 + by, cx - 22, 72 + by, cx - 18, 78 + by)
        p.drawPath(s)

        s2 = QPainterPath()
        s2.moveTo(cx - 6, 54 + by)
        s2.cubicTo(cx - 12, 63 + by, cx - 14, 72 + by, cx - 12, 80 + by)
        p.drawPath(s2)

        # Middle strand
        s3 = QPainterPath()
        s3.moveTo(cx + 2, 53 + by)
        s3.cubicTo(cx - 2, 62 + by, cx - 4, 70 + by, cx - 2, 76 + by)
        p.drawPath(s3)

        # Right fringe
        s4 = QPainterPath()
        s4.moveTo(cx + 10, 55 + by)
        s4.cubicTo(cx + 16, 64 + by, cx + 18, 72 + by, cx + 14, 79 + by)
        p.drawPath(s4)

        # Side locks (longer strands beside face)
        side_pen = QPen(QColor("#3b1d6e"), 2.5, Qt.SolidLine, Qt.RoundCap)
        p.setPen(side_pen)

        # Left side lock
        sl = QPainterPath()
        sl.moveTo(cx - 26, 68 + by)
        sl.cubicTo(cx - 32, 85 + by, cx - 30, 105 + by, cx - 27, 118 + by)
        p.drawPath(sl)

        # Right side lock
        sr = QPainterPath()
        sr.moveTo(cx + 26, 68 + by)
        sr.cubicTo(cx + 32, 85 + by, cx + 30, 105 + by, cx + 27, 118 + by)
        p.drawPath(sr)

    # ---- Rain (SCANNING) ------------------------------------------------------

    def _paint_rain(self, p: QPainter):
        font = QFont("Consolas", 8)
        p.setFont(font)
        for drop in self._rain_drops:
            c = QColor(0, 255, 65, int(drop.opacity * 255))
            p.setPen(c)
            p.drawText(QPointF(drop.x, drop.y), drop.char)

    # ---- Sparkles (SAFE) ------------------------------------------------------

    def _paint_sparkles(self, p: QPainter):
        for s in self._sparkles:
            opacity = (math.sin(s.phase) + 1) / 2  # 0..1
            c = QColor(0, 255, 65, int(opacity * 200))
            p.setBrush(QBrush(c))
            p.setPen(Qt.NoPen)
            p.drawEllipse(QPointF(s.x, s.y), s.size, s.size)

    # ---- Speech bubble --------------------------------------------------------

    def _paint_bubble(self, p: QPainter, cx: float):
        if not self._bubble_display:
            return

        font = QFont("Segoe UI", 7)
        p.setFont(font)

        fm = p.fontMetrics()
        text_w = fm.horizontalAdvance(self._bubble_display) + 16
        text_h = fm.height() + 10
        bw = max(text_w, 50)
        bh = text_h
        bx = cx - bw / 2
        bubble_y = 18  # above the character head
        br = 6  # corner radius

        # Bubble rectangle
        bubble_rect = QRectF(bx, bubble_y, bw, bh)
        bubble_color = QColor("#1e1e2e")
        border_color = QColor("#00ff41")

        p.setBrush(QBrush(bubble_color))
        p.setPen(QPen(border_color, 1.0))
        p.drawRoundedRect(bubble_rect, br, br)

        # Triangle pointer (points down toward head)
        tri = QPainterPath()
        tri.moveTo(cx - 5, bubble_y + bh)
        tri.lineTo(cx, bubble_y + bh + 7)
        tri.lineTo(cx + 5, bubble_y + bh)
        tri.closeSubpath()
        p.setBrush(QBrush(bubble_color))
        p.setPen(QPen(border_color, 1.0))
        p.drawPath(tri)

        # Fill over the gap between bubble and triangle
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(bubble_color))
        p.drawRect(QRectF(cx - 4, bubble_y + bh - 1, 8, 2))

        # Text
        p.setPen(QColor("#00ff41"))
        p.setFont(font)
        p.drawText(bubble_rect, Qt.AlignCenter, self._bubble_display)

    # ------------------------------------------------------------------
    def sizeHint(self):
        return QSize(150, 220)
