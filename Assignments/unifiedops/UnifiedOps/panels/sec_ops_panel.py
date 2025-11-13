# ------------------------------------------------------------
# Security Operations Panel (ASCII Only)
# - SSL Cert Info
# - Port Scanner
# - Host Resolver
# - File Hash Generator
# - System Network Info
# - Website Audit (scrape + broken link check + security checks)
# ------------------------------------------------------------

import os
import socket
import ssl
import threading
import hashlib
import datetime
from urllib.parse import urljoin, urlparse

from PySide6 import QtCore, QtWidgets

# optional third-party imports (requests, bs4)
try:
    import requests
    from bs4 import BeautifulSoup
except Exception:
    requests = None
    BeautifulSoup = None


class SecOpsPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        v = QtWidgets.QVBoxLayout(self)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(8)

        title = QtWidgets.QLabel("Security Operations")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        v.addWidget(title)

        # Tab widget
        self.tabs = QtWidgets.QTabWidget()
        v.addWidget(self.tabs, 1)

        # 1) SSL Cert Tab
        self._build_ssl_tab()

        # 2) Port Scanner Tab
        self._build_port_tab()

        # 3) Resolver Tab
        self._build_resolver_tab()

        # 4) File Hash Tab
        self._build_hash_tab()

        # 5) System Info Tab
        self._build_sysinfo_tab()

        # 6) Website Audit Tab
        self._build_site_audit_tab()

    # --------------------------
    # Utilities
    # --------------------------
    def _append_log(self, widget, text):
        """Thread-safe append for QTextEdit-like widgets."""
        QtCore.QMetaObject.invokeMethod(widget, "append", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, text))

    # --------------------------
    # SSL Tab
    # --------------------------
    def _build_ssl_tab(self):
        w = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(w)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(6)

        row = QtWidgets.QHBoxLayout()
        self.ssl_host = QtWidgets.QLineEdit()
        self.ssl_host.setPlaceholderText("Enter host (example.com)")
        self.ssl_check_btn = QtWidgets.QPushButton("Check Certificate")
        row.addWidget(self.ssl_host, 1)
        row.addWidget(self.ssl_check_btn)
        lay.addLayout(row)

        self.ssl_out = QtWidgets.QTextEdit()
        self.ssl_out.setReadOnly(True)
        lay.addWidget(self.ssl_out, 1)

        self.ssl_check_btn.clicked.connect(self._ssl_check_start)
        self.tabs.addTab(w, "SSL Cert")

    def _ssl_check_start(self):
        host = self.ssl_host.text().strip()
        if not host:
            QtWidgets.QMessageBox.critical(self, "SSL", "Enter host")
            return
        self.ssl_out.clear()
        threading.Thread(target=self._ssl_check_run, args=(host,), daemon=True).start()

    def _ssl_check_run(self, host):
        self._append_log(self.ssl_out, f"Checking {host} ...")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(True)
                    cert = ssock.getpeercert()
                    # extract basic fields
                    subject = cert.get("subject", ())
                    issuer = cert.get("issuer", ())
                    notBefore = cert.get("notBefore")
                    notAfter = cert.get("notAfter")
                    version = ssock.version() if hasattr(ssock, "version") else "unknown"
                    now = datetime.datetime.utcnow()
                    try:
                        expires_dt = datetime.datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
                        expired = expires_dt < now
                    except Exception:
                        expires_dt = notAfter
                        expired = False

                    self._append_log(self.ssl_out, "Subject: %s" % (subject,))
                    self._append_log(self.ssl_out, "Issuer: %s" % (issuer,))
                    self._append_log(self.ssl_out, "Valid From: %s" % (notBefore,))
                    self._append_log(self.ssl_out, "Valid Until: %s" % (notAfter,))
                    self._append_log(self.ssl_out, "TLS Version: %s" % (version,))
                    self._append_log(self.ssl_out, "Expired: %s" % (expired,))
        except Exception as e:
            self._append_log(self.ssl_out, "Error: %s" % e)

    # --------------------------
    # Port Scanner Tab
    # --------------------------
    def _build_port_tab(self):
        w = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(w)
        lay.setContentsMargins(8, 8, 8, 8)

        row = QtWidgets.QHBoxLayout()
        self.port_host = QtWidgets.QLineEdit()
        self.port_host.setPlaceholderText("Enter host or IP")
        self.port_range = QtWidgets.QLineEdit("1-1024")
        self.port_scan_btn = QtWidgets.QPushButton("Scan Ports")
        row.addWidget(self.port_host, 1)
        row.addWidget(self.port_range)
        row.addWidget(self.port_scan_btn)
        lay.addLayout(row)

        self.port_out = QtWidgets.QTextEdit()
        self.port_out.setReadOnly(True)
        lay.addWidget(self.port_out, 1)

        self.port_scan_btn.clicked.connect(self._port_scan_start)
        self.tabs.addTab(w, "Port Scan")

    def _port_scan_start(self):
        host = self.port_host.text().strip()
        rng = self.port_range.text().strip()
        if not host:
            QtWidgets.QMessageBox.critical(self, "Ports", "Enter host")
            return
        try:
            start, end = 1, 1024
            if "-" in rng:
                a, b = rng.split("-", 1)
                start = int(a)
                end = int(b)
        except Exception:
            QtWidgets.QMessageBox.critical(self, "Ports", "Invalid range")
            return
        self.port_out.clear()
        threading.Thread(target=self._port_scan_run, args=(host, start, end), daemon=True).start()

    def _port_scan_run(self, host, start, end, timeout=0.4, max_threads=200):
        self._append_log(self.port_out, "Resolving host...")
        try:
            ip = socket.gethostbyname(host)
            self._append_log(self.port_out, "Host resolved: %s" % ip)
        except Exception as e:
            self._append_log(self.port_out, "Resolve error: %s" % e)
            return

        ports = list(range(max(1, start), max(1, end) + 1))
        open_ports = []
        lock = threading.Lock()
        idx = {"i": 0}

        def worker():
            while True:
                with lock:
                    if idx["i"] >= len(ports):
                        return
                    p = ports[idx["i"]]
                    idx["i"] += 1
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                try:
                    s.connect((ip, p))
                    s.close()
                    with lock:
                        open_ports.append(p)
                        self._append_log(self.port_out, "Open: %d" % p)
                except Exception:
                    pass

        threads = []
        for _ in range(min(max_threads, len(ports))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        open_ports.sort()
        if not open_ports:
            self._append_log(self.port_out, "No open ports found in range.")
        else:
            self._append_log(self.port_out, "Open ports: %s" % (", ".join(str(x) for x in open_ports),))

    # --------------------------
    # Resolver Tab
    # --------------------------
    def _build_resolver_tab(self):
        w = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(w)

        row = QtWidgets.QHBoxLayout()
        self.res_host = QtWidgets.QLineEdit()
        self.res_host.setPlaceholderText("Enter hostname")
        self.res_btn = QtWidgets.QPushButton("Resolve")
        row.addWidget(self.res_host, 1)
        row.addWidget(self.res_btn)
        lay.addLayout(row)

        self.res_out = QtWidgets.QTextEdit()
        self.res_out.setReadOnly(True)
        lay.addWidget(self.res_out, 1)

        self.res_btn.clicked.connect(self._resolve_start)
        self.tabs.addTab(w, "Resolver")

    def _resolve_start(self):
        host = self.res_host.text().strip()
        if not host:
            QtWidgets.QMessageBox.critical(self, "Resolve", "Enter hostname")
            return
        self.res_out.clear()
        try:
            ips = socket.getaddrinfo(host, None)
            seen = set()
            for item in ips:
                ip = item[4][0]
                if ip not in seen:
                    seen.add(ip)
                    self.res_out.append(ip)
        except Exception as e:
            self.res_out.append("Error: %s" % e)

    # --------------------------
    # File Hash Tab
    # --------------------------
    def _build_hash_tab(self):
        w = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(w)

        row = QtWidgets.QHBoxLayout()
        self.hash_path = QtWidgets.QLineEdit()
        self.hash_path.setPlaceholderText("Select file path or paste path")
        self.hash_btn = QtWidgets.QPushButton("Browse")
        self.hash_calc = QtWidgets.QPushButton("Compute Hashes")
        row.addWidget(self.hash_path, 1)
        row.addWidget(self.hash_btn)
        row.addWidget(self.hash_calc)
        lay.addLayout(row)

        self.hash_out = QtWidgets.QTextEdit()
        self.hash_out.setReadOnly(True)
        lay.addWidget(self.hash_out, 1)

        self.hash_btn.clicked.connect(self._browse_file)
        self.hash_calc.clicked.connect(self._hash_start)
        self.tabs.addTab(w, "File Hash")

    def _browse_file(self):
        p, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select File", "")
        if p:
            self.hash_path.setText(p)

    def _hash_start(self):
        path = self.hash_path.text().strip()
        if not path or not os.path.isfile(path):
            QtWidgets.QMessageBox.critical(self, "Hash", "Select a valid file")
            return
        self.hash_out.clear()
        threading.Thread(target=self._hash_run, args=(path,), daemon=True).start()

    def _hash_run(self, path):
        try:
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha256.update(chunk)
                    md5.update(chunk)
            self._append_log(self.hash_out, "MD5: %s" % md5.hexdigest())
            self._append_log(self.hash_out, "SHA256: %s" % sha256.hexdigest())
        except Exception as e:
            self._append_log(self.hash_out, "Error: %s" % e)

    # --------------------------
    # System Info Tab
    # --------------------------
    def _build_sysinfo_tab(self):
        w = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(w)

        btns = QtWidgets.QHBoxLayout()
        self.sys_refresh = QtWidgets.QPushButton("Refresh Info")
        btns.addWidget(self.sys_refresh)
        lay.addLayout(btns)

        self.sys_out = QtWidgets.QTextEdit()
        self.sys_out.setReadOnly(True)
        lay.addWidget(self.sys_out, 1)

        self.sys_refresh.clicked.connect(self._sysinfo_run)
        self.tabs.addTab(w, "System Info")

    def _sysinfo_run(self):
        out_lines = []
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            out_lines.append("Hostname: %s" % hostname)
            out_lines.append("Local IP: %s" % local_ip)
            # external IP
            ext_ip = "unavailable"
            if requests:
                try:
                    r = requests.get("https://api.ipify.org", timeout=5)
                    if r.status_code == 200:
                        ext_ip = r.text.strip()
                except Exception:
                    pass
            out_lines.append("External IP: %s" % ext_ip)
            self.sys_out.setText("\n".join(out_lines))
        except Exception as e:
            self.sys_out.setText("Error: %s" % e)

    # --------------------------
    # Website Audit Tab
    # --------------------------
    def _build_site_audit_tab(self):
        w = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(w)

        row = QtWidgets.QHBoxLayout()
        self.site_url = QtWidgets.QLineEdit()
        self.site_url.setPlaceholderText("Enter site URL (e.g. https://example.com)")
        self.site_audit_btn = QtWidgets.QPushButton("Run Site Audit")
        row.addWidget(self.site_url, 1)
        row.addWidget(self.site_audit_btn)
        lay.addLayout(row)

        self.site_out = QtWidgets.QTextEdit()
        self.site_out.setReadOnly(True)
        lay.addWidget(self.site_out, 1)

        self.site_audit_btn.clicked.connect(self._site_audit_start)
        self.tabs.addTab(w, "Site Audit")

    def _site_audit_start(self):
        url = self.site_url.text().strip()
        if not url:
            QtWidgets.QMessageBox.critical(self, "Site Audit", "Enter site URL")
            return
        if not requests or not BeautifulSoup:
            QtWidgets.QMessageBox.critical(self, "Site Audit", "Requires requests and beautifulsoup4 installed")
            return
        self.site_out.clear()
        threading.Thread(target=self._site_audit_run, args=(url,), daemon=True).start()

    def _site_audit_run(self, url):
        self._append_log(self.site_out, "Starting site audit for: %s" % url)
        parsed = urlparse(url)
        base = parsed.scheme + "://" + parsed.netloc

        # fetch main page
        try:
            r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            status = r.status_code
            self._append_log(self.site_out, "Main page status: %s" % status)
            html = r.text
        except Exception as e:
            self._append_log(self.site_out, "Fetch error: %s" % e)
            return

        # security headers
        headers = r.headers or {}
        required = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ]
        missing = [h for h in required if h not in (k.lower() for k in headers.keys())]
        if missing:
            self._append_log(self.site_out, "Missing security headers: %s" % ", ".join(missing))
        else:
            self._append_log(self.site_out, "Security headers: OK")

        # robots
        try:
            robots_r = requests.get(urljoin(base, "/robots.txt"), timeout=6)
            if robots_r.status_code == 200 and robots_r.text.strip():
                self._append_log(self.site_out, "Found robots.txt")
            else:
                self._append_log(self.site_out, "No robots.txt or empty")
        except Exception:
            self._append_log(self.site_out, "Robots check failed")

        # check .git
        try:
            git_r = requests.get(urljoin(base, "/.git/HEAD"), timeout=6)
            if git_r.status_code == 200 and "ref:" in git_r.text:
                self._append_log(self.site_out, ".git appears exposed")
            else:
                self._append_log(self.site_out, ".git exposure: not found")
        except Exception:
            self._append_log(self.site_out, ".git check failed")

        # parse links
        soup = BeautifulSoup(html, "html.parser")
        anchors = [a.get("href") for a in soup.find_all("a", href=True)]
        imgs = [i.get("src") for i in soup.find_all("img", src=True)]
        scripts = [s.get("src") for s in soup.find_all("script", src=True)]
        iframes = [f.get("src") for f in soup.find_all("iframe", src=True)]

        # normalize and filter
        def norm(u):
            try:
                return urljoin(base, u)
            except Exception:
                return u

        links = set()
        for col in (anchors, imgs, scripts, iframes):
            for x in col:
                if not x:
                    continue
                nx = norm(x)
                pr = urlparse(nx)
                if pr.scheme in ("http", "https"):
                    links.add(nx)

        links = sorted(list(links))
        self._append_log(self.site_out, "Found %d distinct links/resources" % len(links))

        # multi-threaded link checking
        results = []
        lock = threading.Lock()
        idx = {"i": 0}

        def check_worker():
            while True:
                with lock:
                    if idx["i"] >= len(links):
                        return
                    i = idx["i"]
                    idx["i"] += 1
                link = links[i]
                try:
                    head = requests.head(link, allow_redirects=True, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
                    code = head.status_code
                    if code >= 400:
                        # try GET in case server blocks HEAD
                        g = requests.get(link, allow_redirects=True, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                        code = g.status_code
                    entry = (link, code)
                except Exception as e:
                    entry = (link, None)
                with lock:
                    results.append(entry)
                    # incremental UI update
                    s = entry[1] if entry[1] is not None else "ERR"
                    self._append_log(self.site_out, "%s -> %s" % (entry[0], s))

        threads = []
        max_threads = min(20, max(4, len(links)//5))
        for _ in range(max_threads):
            t = threading.Thread(target=check_worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        # group results
        broken = [e for e in results if e[1] is None or (isinstance(e[1], int) and e[1] >= 400)]
        redirects = [e for e in results if isinstance(e[1], int) and 300 <= e[1] <= 399]
        good = [e for e in results if isinstance(e[1], int) and 200 <= e[1] <= 299]

        # write report.txt in current working dir
        try:
            with open("site_audit_report.txt", "w", encoding="utf-8") as f:
                f.write("Site Audit Report for: %s\n\n" % base)
                f.write("[BROKEN]\n")
                for e in broken:
                    f.write("%s %s\n" % (e[1], e[0]))
                f.write("\n[REDIRECTS]\n")
                for e in redirects:
                    f.write("%s %s\n" % (e[1], e[0]))
                f.write("\n[GOOD]\n")
                for e in good:
                    f.write("%s %s\n" % (e[1], e[0]))
            self._append_log(self.site_out, "Report written to site_audit_report.txt")
        except Exception as e:
            self._append_log(self.site_out, "Failed to write report: %s" % e)

        self._append_log(self.site_out, "Audit complete.")
