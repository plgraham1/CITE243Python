# ------------------------------------------------------------
# Regex Search Panel (ASCII Only)
# ------------------------------------------------------------
import re
from PySide6 import QtCore, QtWidgets

class RegexPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        title = QtWidgets.QLabel("Regex Search Tool")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        layout.addWidget(title)

        self.pattern_edit = QtWidgets.QLineEdit()
        self.pattern_edit.setPlaceholderText("Enter regular expression...")
        layout.addWidget(self.pattern_edit)

        self.text_edit = QtWidgets.QPlainTextEdit()
        self.text_edit.setPlaceholderText("Enter text to search...")
        layout.addWidget(self.text_edit)

        self.output = QtWidgets.QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        self.button = QtWidgets.QPushButton("Run Regex Search")
        layout.addWidget(self.button)
        self.button.clicked.connect(self.run_search)

    def run_search(self):
        pattern = self.pattern_edit.text().strip()
        text = self.text_edit.toPlainText()

        if not pattern:
            self.output.setText("Error: No regex pattern entered.")
            return

        try:
            matches = re.findall(pattern, text)
            if matches:
                self.output.setText("Matches found:\n" + "\n".join(matches))
            else:
                self.output.setText("No matches found.")
        except re.error as e:
            self.output.setText("Regex error: %s" % e)
