# ------------------------------------------------------------
# Link Verifier Panel (ASCII Only)
# ------------------------------------------------------------
from PySide6 import QtCore, QtWidgets
import requests

class LinkVerifierPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        title = QtWidgets.QLabel("Link Verifier")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        layout.addWidget(title)

        self.input = QtWidgets.QPlainTextEdit()
        self.input.setPlaceholderText("Enter one or more URLs (one per line)...")
        layout.addWidget(self.input)

        self.result = QtWidgets.QTextEdit()
        self.result.setReadOnly(True)
        layout.addWidget(self.result)

        self.button = QtWidgets.QPushButton("Check Links")
        layout.addWidget(self.button)
        self.button.clicked.connect(self.check_links)

    def check_links(self):
        urls = [u.strip() for u in self.input.toPlainText().splitlines() if u.strip()]
        if not urls:
            self.result.setText("No URLs entered.")
            return

        self.result.setText("Checking links...\n")
        for url in urls:
            QtCore.QCoreApplication.processEvents()
            try:
                r = requests.head(url, allow_redirects=True, timeout=5)
                self.result.append("%s -> %s" % (url, r.status_code))
            except Exception as e:
                self.result.append("%s -> ERROR (%s)" % (url, e))
