# ui/theme.py
from PySide6 import QtGui

class OpsTheme:
    # LCARS Colors
    BG = QtGui.QColor("#010101")        # Near-black LCARS background
    FG = QtGui.QColor("#E6AD63")        # LCARS amber text
    PANEL = QtGui.QColor("#5A79FF")     # Blue panel bar
    ACCENT = QtGui.QColor("#FF9B00")    # LCARS orange button
    ALERT = QtGui.QColor("#FF5555")     # Red alert
    OK = QtGui.QColor("#8CFF4D")        # LCARS green

    # UI Sizes
    BUTTON_HEIGHT = 48
    PILL_RADIUS = 14

    # Fonts
    FONT_FAMILY = "Segoe UI"
    HEADER_SIZE = 22
    BODY_SIZE = 11

    @staticmethod
    def font(size=None, bold=False):
        f = QtGui.QFont(OpsTheme.FONT_FAMILY)
        f.setPointSize(size or OpsTheme.BODY_SIZE)
        f.setBold(bold)
        return f

    @staticmethod
    def style_sheet():
        # Global theme (applies to entire app)
        return """
        QWidget {
            background-color: #010101;
            color: #E6AD63;
        }
        QPushButton {
            background-color: #FF9B00;
            color: black;
            padding: 10px;
            border-radius: 14px;
            font-weight: bold;
        }
        QPushButton:checked {
            background-color: #5A79FF;
            color: white;
        }
        QLineEdit, QTextEdit, QComboBox {
            background-color: #111111;
            border: 2px solid #5A79FF;
            color: #E6AD63;
            padding: 6px;
            border-radius: 6px;
        }
        QLabel {
            color: #E6AD63;
        }
        """
