"""Configure PySide6 mocks for testing without a display server."""
import sys
from unittest.mock import MagicMock

# Only mock if PySide6 is not actually installed
try:
    import PySide6
except ImportError:

    class FakeSignal:
        """Mimics PySide6.QtCore.Signal for testing."""
        def __init__(self, *args, **kwargs):
            self._callbacks = []

        def connect(self, callback):
            self._callbacks.append(callback)

        def emit(self, *args, **kwargs):
            for cb in self._callbacks:
                cb(*args, **kwargs)

        def __call__(self, *args, **kwargs):
            return self

    class FakeSlot:
        def __call__(self, *args, **kwargs):
            if args and callable(args[0]):
                return args[0]
            def decorator(func):
                return func
            return decorator

    class FakeQObject:
        def __init__(self, parent=None):
            pass

    class FakeQThread(FakeQObject):
        def __init__(self, parent=None):
            super().__init__(parent)
            self._running = False

        def start(self):
            self._running = True

        def wait(self, timeout=None):
            pass

        def isRunning(self):
            return self._running

        def msleep(self, ms):
            pass

    class FakeQMutex:
        def lock(self):
            pass

        def unlock(self):
            pass

    # Build mock module hierarchy
    qt_core = MagicMock()
    qt_core.Signal = FakeSignal
    qt_core.Slot = FakeSlot()
    qt_core.QObject = FakeQObject
    qt_core.QThread = FakeQThread
    qt_core.QMutex = FakeQMutex
    qt_core.Qt = MagicMock()
    qt_core.QTimer = MagicMock()

    qt_widgets = MagicMock()
    qt_widgets.QApplication = MagicMock()
    qt_widgets.QMainWindow = type("QMainWindow", (), {"__init__": lambda self, *a, **kw: None})
    qt_widgets.QWidget = type("QWidget", (), {"__init__": lambda self, *a, **kw: None})
    qt_widgets.QFrame = type("QFrame", (), {
        "__init__": lambda self, *a, **kw: None,
        "StyledPanel": 0,
    })
    qt_widgets.QTabWidget = MagicMock()
    qt_widgets.QVBoxLayout = MagicMock(return_value=MagicMock())
    qt_widgets.QHBoxLayout = MagicMock(return_value=MagicMock())
    qt_widgets.QLabel = MagicMock()
    qt_widgets.QComboBox = MagicMock()
    qt_widgets.QPushButton = MagicMock()
    qt_widgets.QLineEdit = MagicMock()
    qt_widgets.QTableWidget = MagicMock()
    qt_widgets.QTableWidgetItem = MagicMock()
    qt_widgets.QHeaderView = MagicMock()

    pyside_mock = MagicMock()
    pyside_mock.QtCore = qt_core
    pyside_mock.QtWidgets = qt_widgets

    sys.modules["PySide6"] = pyside_mock
    sys.modules["PySide6.QtCore"] = qt_core
    sys.modules["PySide6.QtWidgets"] = qt_widgets
    sys.modules["PySide6.QtGui"] = MagicMock()

# Mock pyqtgraph if not installed
try:
    import pyqtgraph
except ImportError:
    sys.modules["pyqtgraph"] = MagicMock()

# Mock pglive if not installed
try:
    import pglive
except ImportError:
    sys.modules["pglive"] = MagicMock()

# Mock plyer if not installed
try:
    import plyer
except ImportError:
    sys.modules["plyer"] = MagicMock()
    sys.modules["plyer.notification"] = MagicMock()
