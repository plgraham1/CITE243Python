# ============================================================
# Builder Panel
# ============================================================

import subprocess
import threading
from pathlib import Path
from PySide6 import QtCore, QtWidgets


class BuilderPanel(QtWidgets.QWidget):
    """
    This panel allows users to build executable installers for
    Python applications using PyInstaller and optionally Inno Setup.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        title = QtWidgets.QLabel("Application Builder")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        layout.addWidget(title)

        desc = QtWidgets.QLabel(
            "This tool builds Windows executables (.exe) from Python scripts."
        )
        layout.addWidget(desc)

        self.path_edit = QtWidgets.QLineEdit()
        self.path_edit.setPlaceholderText("Select Python script to build...")
        layout.addWidget(self.path_edit)

        browse_btn = QtWidgets.QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        layout.addWidget(browse_btn)

        self.status = QtWidgets.QTextEdit()
        self.status.setReadOnly(True)
        layout.addWidget(self.status)

        build_btn = QtWidgets.QPushButton("Build Executable")
        build_btn.clicked.connect(self.run_builder)
        layout.addWidget(build_btn)

        self.setLayout(layout)

    # ------------------------------------------------------------
    # File selection
    # ------------------------------------------------------------
    def browse_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select Python Script", str(Path.home()), "Python Files (*.py)"
        )
        if path:
            self.path_edit.setText(path)

    # ------------------------------------------------------------
    # Run the builder
    # ------------------------------------------------------------
    def run_builder(self):
        target = self.path_edit.text().strip()
        if not target:
            self.status.append("Error: No file selected.")
            return

        out_dir = Path(target).parent / "dist"
        self.status.append("Starting build process...")
        self.status.append("Output directory: " + str(out_dir))

        cmd = ["pyinstaller", "--onefile", "--noconsole", target]

        def build_thread():
            try:
                subprocess.call(cmd)
                QtCore.QMetaObject.invokeMethod(
                    self, "_notify_success", QtCore.Qt.QueuedConnection
                )
            except Exception as e:
                QtCore.QMetaObject.invokeMethod(
                    self,
                    "_notify_failure",
                    QtCore.Qt.QueuedConnection,
                    QtCore.Q_ARG(str, str(e)),
                )

        threading.Thread(target=build_thread, daemon=True).start()

    # ------------------------------------------------------------
    # Build result feedback
    # ------------------------------------------------------------
    @QtCore.Slot()
    def _notify_success(self):
        self.status.append("Build complete!")

    @QtCore.Slot(str)
    def _notify_failure(self, msg):
        self.status.append("Build failed: " + msg)
