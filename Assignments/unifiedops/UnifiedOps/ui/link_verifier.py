# ============================================================
# Link Verifier Panel
# ============================================================

import threading
import requests
from PySide6 import QtCore, QtWidgets


class LinkVerifierPanel(QtWidgets.QWidget):
    """
    Checks URLs or domains to see if they are reachable.
    Displays HTTP response codes and errors.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        title = QtWidgets.QLabel("Link Verifier")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        layout.addWidget(title)

        desc = QtWidgets.QLabel(
            "Enter one or more URLs (one per line) to check their status."
        )
        layout.addWidget(desc)

        self.input_box = QtWidgets.QTextEdit()
        self.input_box.setPlaceholderText("https://example.com\nhttps://another-site.com")
        layout.addWidget(self.input_box)

        self.log = QtWidgets.QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)

        btn_check = QtWidgets.QPushButton("Check Links")
        btn_clear = QtWidgets.QPushButton("Clear Log")

        layout.addWidget(btn_check)
        layout.addWidget(btn_clear)

        btn_check.clicked.connect(self.run_check)
        btn_clear.clicked.connect(lambda: self.log.clear())

    # ------------------------------------------------------------
    # Run checks in background thread
    # ------------------------------------------------------------
    def run_check(self):
        urls = [u.strip() for u in self.input_box.toPlainText().splitlines() if u.strip()]
        if not urls:
            self.log.append("Error: No URLs provided.")
            return

        self.log.append("Starting link verification...")
        threading.Thread(target=self._verify_links, args=(urls,), daemon=True).start()

    # ------------------------------------------------------------
    # Verify links
    # ------------------------------------------------------------
    def _verify_links(self, urls):
        for url in urls:
            try:
                response = requests.head(url, timeout=5)
                code = response.status_code
                if code == 200:
                    msg = "[OK] " + url + " (200)"
                else:
                    msg = "[WARN] " + url + " (" + str(code) + ")"
            except Exception as e:
                msg = "[ERROR] " + url + " -> " + str(e)

            # update UI from main thread
            QtCore.QMetaObject.invokeMethod(
                self, "_append_log",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(str, msg)
            )

    @QtCore.Slot(str)
    def _append_log(self, message):
        self.log.append(message)
