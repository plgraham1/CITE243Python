# ============================================================
# Google Tools Panel
# ============================================================

from pathlib import Path
from PySide6 import QtWidgets
from helpers import extract_google_id, ensure_folder, get_documents_folder


class GoogleToolsPanel(QtWidgets.QWidget):
    """
    Provides tools to interact with Google Sheets using EZSheets.
    Features:
      - Download Google Form responses
      - Convert spreadsheets into other formats
      - Find math mistakes in sheets
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        title = QtWidgets.QLabel("Google Sheets Automation Tools")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        layout.addWidget(title)

        desc = QtWidgets.QLabel(
            "Use these tools to work with Google Sheets data. "
            "Enter a shared link or sheet ID when prompted."
        )
        layout.addWidget(desc)

        self.log = QtWidgets.QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)

        btn_form = QtWidgets.QPushButton("Download Form Data")
        btn_convert = QtWidgets.QPushButton("Convert Spreadsheet Formats")
        btn_check = QtWidgets.QPushButton("Find Spreadsheet Mistakes")

        layout.addWidget(btn_form)
        layout.addWidget(btn_convert)
        layout.addWidget(btn_check)

        btn_form.clicked.connect(self.download_form_data)
        btn_convert.clicked.connect(self.convert_spreadsheet)
        btn_check.clicked.connect(self.find_mistakes)

    # ------------------------------------------------------------
    # 1. Download Google Form responses
    # ------------------------------------------------------------
    def download_form_data(self):
        import ezsheets

        link, ok = QtWidgets.QInputDialog.getText(
            self, "Google Sheet Link", "Enter shared link or Sheet ID:"
        )
        if not ok or not link.strip():
            return

        try:
            sheet_id = extract_google_id(link)
            self.log.append("Connecting to Google Sheet ID: " + sheet_id)
            ss = ezsheets.Spreadsheet(sheet_id)
            sheet = ss[0]
            rows = sheet.getRows()
            headers = rows[0]
            data = rows[1:]
            self.log.append("Found " + str(len(data)) + " rows of data.")
            csv_path = get_documents_folder() / "Google_Form_Data.csv"
            ensure_folder(csv_path.parent)

            with open(csv_path, "w", encoding="utf-8") as f:
                f.write(",".join(headers) + "\n")
                for row in data:
                    f.write(",".join(row) + "\n")

            self.log.append("Data saved to: " + str(csv_path))
        except Exception as e:
            self.log.append("Error: " + str(e))

    # ------------------------------------------------------------
    # 2. Convert Google Sheet into multiple formats
    # ------------------------------------------------------------
    def convert_spreadsheet(self):
        import ezsheets

        link, ok = QtWidgets.QInputDialog.getText(
            self, "Google Sheet Link", "Enter shared link or Sheet ID:"
        )
        if not ok or not link.strip():
            return

        try:
            sheet_id = extract_google_id(link)
            self.log.append("Downloading Google Sheet ID: " + sheet_id)
            ss = ezsheets.Spreadsheet(sheet_id)
            out_dir = ensure_folder(get_documents_folder() / "Google_Exports")

            ss.downloadAsExcel(str(out_dir / (ss.title + ".xlsx")))
            ss.downloadAsODS(str(out_dir / (ss.title + ".ods")))
            ss.downloadAsCSV(str(out_dir / (ss.title + ".csv")))

            self.log.append("Files saved to: " + str(out_dir))
        except Exception as e:
            self.log.append("Error: " + str(e))

    # ------------------------------------------------------------
    # 3. Find math mistakes in spreadsheet
    # ------------------------------------------------------------
    def find_mistakes(self):
        import ezsheets

        link, ok = QtWidgets.QInputDialog.getText(
            self, "Google Sheet Link", "Enter shared link or Sheet ID:"
        )
        if not ok or not link.strip():
            return

        try:
            sheet_id = extract_google_id(link)
            self.log.append("Checking totals in Sheet ID: " + sheet_id)
            ss = ezsheets.Spreadsheet(sheet_id)
            sheet = ss[0]

            for row_num in range(2, sheet.rowCount + 1):
                row = sheet.getRow(row_num)
                if len(row) < 3 or not all(row[:3]):
                    continue
                try:
                    if int(row[0]) * int(row[1]) != int(row[2]):
                        self.log.append("Error found in row " + str(row_num) + ": " + str(row))
                        break
                except ValueError:
                    continue
            else:
                self.log.append("No mistakes found.")
        except Exception as e:
            self.log.append("Error: " + str(e))
