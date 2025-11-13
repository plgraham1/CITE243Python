# ui/widgets.py
from PySide6 import QtCore, QtGui, QtWidgets
from ui.theme import OpsTheme


class Header(QtWidgets.QLabel):
    def __init__(self):
        super().__init__("UNIFIED OPERATIONS SHELL")
        self.setAlignment(QtCore.Qt.AlignCenter)
        self.setFont(OpsTheme.font(OpsTheme.HEADER_SIZE, bold=True))
        self.setStyleSheet(
            "background:{bg}; color:{fg}; padding:12px; border-radius:6px;".format(
                bg=OpsTheme.PANEL.name(),
                fg=OpsTheme.FG.name()
            )
        )


class Sidebar(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()

        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(12, 20, 12, 12)

        self.buttons = []
        labels = [
            "SEC OPS",
            "Regex Search",
            "File Tools",
            "Builder",
            "Link Verifier",
            "Google Tools",
            "Meal Database",
            "PDF Tools"
        ]

        self._anims = []  # store animations
        delay_ms = 0

        for text in labels:
            btn = QtWidgets.QPushButton(text)
            btn.setMinimumHeight(
                getattr(OpsTheme, "BUTTON_HEIGHT", 44)
            )
            btn.setFont(OpsTheme.font(12, bold=True))
            btn.setCheckable(True)

            btn.setStyleSheet(
                "background:{accent}; color:black; padding:8px; "
                "border-radius:{radius}px;".format(
                    accent=OpsTheme.ACCENT.name(),
                    radius=getattr(OpsTheme, "PILL_RADIUS", 14)
                )
            )

            # opacity effect
            effect = QtWidgets.QGraphicsOpacityEffect(btn)
            btn.setGraphicsEffect(effect)
            effect.setOpacity(0)

            layout.addWidget(btn)
            self.buttons.append(btn)

            # fade animation
            anim = QtCore.QPropertyAnimation(effect, b"opacity", self)
            anim.setDuration(600)
            anim.setStartValue(0)
            anim.setEndValue(1)
            anim.setEasingCurve(QtCore.QEasingCurve.OutCubic)

            QtCore.QTimer.singleShot(delay_ms, anim.start)
            delay_ms += 120

            self._anims.append(anim)

        layout.addStretch(1)



class WorkArea(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        self.banner = QtWidgets.QLabel("WELCOME")
        self.banner.setAlignment(QtCore.Qt.AlignCenter)
        self.banner.setFont(OpsTheme.font(14, bold=True))
        self.banner.setStyleSheet(
            "font-size:18px; color:{accent}; padding:6px; border-radius:6px;".format(
                accent=OpsTheme.ACCENT.name()
            )
        )
        layout.addWidget(self.banner)

        self.stack = QtWidgets.QStackedWidget()
        layout.addWidget(self.stack, 1)

    def set_page(self, widget, title, color):
        self.banner.setText(title)
        self.banner.setStyleSheet(
            "font-size:18px; color:{c}; padding:6px; border-radius:6px;".format(
                c=color.name()
            )
        )

        if self.stack.indexOf(widget) == -1:
            self.stack.addWidget(widget)

        self.stack.setCurrentWidget(widget)
