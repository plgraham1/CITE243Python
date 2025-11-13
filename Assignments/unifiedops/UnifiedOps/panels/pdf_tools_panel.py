# ============================================================
# PDF Tools Panel - UnifiedOps
# ============================================================

import os
import hashlib
from pathlib import Path
from PySide6 import QtWidgets, QtGui, QtCore
from PyPDF2 import PdfReader, PdfWriter
from PIL import Image

class PDFToolsPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(6, 6, 6, 6)

        title = QtWidgets.QLabel("PDF Security and Management Tools")
        title.setAlignment(QtCore.Qt.AlignCenter)
        title.setStyleSheet("font-size:18px; font-weight:bold;")
        layout.addWidget(title)

        self.log = QtWidgets.QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log, 1)

        btns = [
            ("Encrypt PDFs in Folder", self.encrypt_pdfs),
            ("Decrypt PDFs in Folder", self.decrypt_pdfs),
            ("Merge PDFs", self.merge_pdfs),
            ("Split PDF Pages", self.split_pdf),
            ("Extract Text", self.extract_text),
            ("Extract Images", self.extract_images),
            ("Remove PDF Metadata", self.strip_metadata),
            ("PDF Inventory Report", self.inventory_report),
            ("Search PDFs for Word", self.search_pdfs),
            ("Find Duplicate PDFs", self.find_duplicates)
        ]

        for text, func in btns:
            b = QtWidgets.QPushButton(text)
            b.clicked.connect(func)
            layout.addWidget(b)

    def choose_folder(self, title):
        return QtWidgets.QFileDialog.getExistingDirectory(self, title)

    def choose_file(self, title):
        return QtWidgets.QFileDialog.getOpenFileName(self, title, "", "PDF Files (*.pdf)")[0]

    def log_msg(self, msg):
        self.log.append(msg)
        print(msg)

    # ------------------------------------------------------------
    # Encrypt PDFs
    # ------------------------------------------------------------
    def encrypt_pdfs(self):
        folder = self.choose_folder("Choose folder to encrypt")
        if not folder:
            return
        pwd, ok = QtWidgets.QInputDialog.getText(self, "Password", "Enter password:")
        if not ok or not pwd:
            return

        for root, dirs, files in os.walk(folder):
            for f in files:
                if f.lower().endswith(".pdf") and "_encrypted" not in f:
                    path = Path(root) / f
                    new = Path(root) / (path.stem + "_encrypted.pdf")

                    try:
                        reader = PdfReader(str(path))
                        writer = PdfWriter()
                        for page in reader.pages:
                            writer.add_page(page)
                        writer.encrypt(pwd)

                        with open(new, "wb") as out:
                            writer.write(out)

                        # test decrypt
                        test = PdfReader(str(new))
                        test.decrypt(pwd)

                        self.log_msg("Encrypted: " + str(path))
                    except Exception as e:
                        self.log_msg("Error encrypting " + str(path) + " : " + str(e))

    # ------------------------------------------------------------
    # Decrypt PDFs
    # ------------------------------------------------------------
    def decrypt_pdfs(self):
        folder = self.choose_folder("Choose folder to decrypt")
        if not folder:
            return
        pwd, ok = QtWidgets.QInputDialog.getText(self, "Password", "Enter password:")
        if not ok or not pwd:
            return

        for root, dirs, files in os.walk(folder):
            for f in files:
                if f.lower().endswith("_encrypted.pdf"):
                    path = Path(root) / f
                    new = Path(root) / (path.stem.replace("_encrypted", "") + "_decrypted.pdf")

                    try:
                        reader = PdfReader(str(path))
                        if reader.decrypt(pwd) != 1:
                            self.log_msg("Wrong password for " + str(path))
                            continue

                        writer = PdfWriter()
                        for page in reader.pages:
                            writer.add_page(page)
                        with open(new, "wb") as out:
                            writer.write(out)

                        self.log_msg("Decrypted: " + str(path))
                    except Exception as e:
                        self.log_msg("Error decrypting " + str(path) + " : " + str(e))

    # ------------------------------------------------------------
    # Merge PDFs
    # ------------------------------------------------------------
    def merge_pdfs(self):
        files, _ = QtWidgets.QFileDialog.getOpenFileNames(
            self, "Select PDFs", "", "PDF Files (*.pdf)"
        )
        if not files:
            return

        save, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save merged PDF", "", "PDF Files (*.pdf)")
        if not save:
            return

        writer = PdfWriter()

        for f in files:
            try:
                reader = PdfReader(f)
                for page in reader.pages:
                    writer.add_page(page)
                self.log_msg("Added: " + f)
            except Exception as e:
                self.log_msg("Error reading: " + f)

        with open(save, "wb") as out:
            writer.write(out)

        self.log_msg("Merged PDF saved: " + save)

    # ------------------------------------------------------------
    # Split PDF
    # ------------------------------------------------------------
    def split_pdf(self):
        pdf = self.choose_file("Choose PDF to split")
        if not pdf:
            return

        reader = PdfReader(pdf)
        out_folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if not out_folder:
            return

        for i, page in enumerate(reader.pages):
            writer = PdfWriter()
            writer.add_page(page)
            out = Path(out_folder) / (Path(pdf).stem + "_page_" + str(i+1) + ".pdf")
            with open(out, "wb") as f:
                writer.write(f)

        self.log_msg("PDF split completed.")

    # ------------------------------------------------------------
    # Extract Text
    # ------------------------------------------------------------
    def extract_text(self):
        pdf = self.choose_file("Choose PDF to extract text from")
        if not pdf:
            return

        reader = PdfReader(pdf)
        save = Path(pdf).with_suffix(".txt")

        with open(save, "w", encoding="utf8") as out:
            for page in reader.pages:
                out.write(page.extract_text() or "")

        self.log_msg("Text saved to: " + str(save))

    # ------------------------------------------------------------
    # Extract Images
    # ------------------------------------------------------------
    def extract_images(self):
        pdf = self.choose_file("Choose PDF to extract images from")
        if not pdf:
            return

        reader = PdfReader(pdf)
        out_dir = Path(pdf).stem + "_images"
        Path(out_dir).mkdir(exist_ok=True)

        count = 0
        for page in reader.pages:
            if "/XObject" in page["/Resources"]:
                xobj = page["/Resources"]["/XObject"]
                for obj in xobj:
                    if xobj[obj]["/Subtype"] == "/Image":
                        data = xobj[obj]._data
                        out = Path(out_dir) / ("image_" + str(count) + ".png")
                        with open(out, "wb") as f:
                            f.write(data)
                        count += 1

        self.log_msg("Extracted " + str(count) + " images.")

    # ------------------------------------------------------------
    # Remove Metadata
    # ------------------------------------------------------------
    def strip_metadata(self):
        pdf = self.choose_file("Choose PDF")
        if not pdf:
            return

        reader = PdfReader(pdf)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        writer.add_metadata({})  # strip metadata

        out = Path(pdf).with_name(Path(pdf).stem + "_clean.pdf")
        with open(out, "wb") as f:
            writer.write(f)

        self.log_msg("Metadata removed. Saved as: " + str(out))

    # ------------------------------------------------------------
    # PDF Inventory
    # ------------------------------------------------------------
    def inventory_report(self):
        folder = self.choose_folder("Choose folder")
        if not folder:
            return

        count = 0
        for root, dirs, files in os.walk(folder):
            for f in files:
                if f.lower().endswith(".pdf"):
                    count += 1
                    path = Path(root) / f
                    size = path.stat().st_size
                    self.log_msg(f"{path} - {size} bytes")

        self.log_msg("Total PDFs found: " + str(count))

    # ------------------------------------------------------------
    # Search PDFs
    # ------------------------------------------------------------
    def search_pdfs(self):
        folder = self.choose_folder("Choose folder")
        if not folder:
            return
        word, ok = QtWidgets.QInputDialog.getText(self, "Search Word", "Word to search:")
        if not ok or not word.strip():
            return

        word = word.lower()

        for root, dirs, files in os.walk(folder):
            for f in files:
                if f.lower().endswith(".pdf"):
                    try:
                        reader = PdfReader(str(Path(root) / f))
                        for page in reader.pages:
                            text = (page.extract_text() or "").lower()
                            if word in text:
                                self.log_msg("Found in: " + str(Path(root) / f))
                                break
                    except:
                        pass

    # ------------------------------------------------------------
    # Find Duplicate PDFs (hash compare)
    # ------------------------------------------------------------
    def find_duplicates(self):
        folder = self.choose_folder("Choose folder")
        if not folder:
            return

        hashes = {}
        for root, dirs, files in os.walk(folder):
            for f in files:
                if f.lower().endswith(".pdf"):
                    path = Path(root) / f
                    h = hashlib.md5(open(path, "rb").read()).hexdigest()
                    if h in hashes:
                        self.log_msg("Duplicate found:")
                        self.log_msg(str(path))
                        self.log_msg("Matches: " + hashes[h])
                    else:
                        hashes[h] = str(path)
