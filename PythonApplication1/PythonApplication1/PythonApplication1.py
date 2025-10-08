import json
import socket
import ssl
import threading
import time
import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from urllib.parse import urljoin, urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

APP_TITLE = "Deep Single Target Inspector (SSL Edition)"

COMMON_ADMIN_PATHS = [
    "/admin/", "/administrator/", "/login/", "/wp-admin/", "/wp-login.php",
    "/phpmyadmin/", "/pma/", "/.git/", "/.env", "/config.php", "/admin.php",
    "/server-status", "/actuator", "/console", "/adminer.php"
]

REMEDIATION_GUIDE = {
    "strict-transport-security":
        "Enable HTTPS and add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "content-security-policy":
        "Add Content-Security-Policy to restrict allowed sources of scripts, styles, etc.",
    "x-frame-options":
        "Set X-Frame-Options: SAMEORIGIN to prevent clickjacking.",
    "x-content-type-options":
        "Set X-Content-Type-Options: nosniff to prevent MIME sniffing.",
    "referrer-policy":
        "Set Referrer-Policy: no-referrer-when-downgrade or stricter.",
    "permissions-policy":
        "Add Permissions-Policy to control browser features usage.",
    "git_exposed":
        "Block access to /.git paths in the web server and remove repository data from public hosts.",
    "common_paths":
        "Lock down default admin panels, require authentication, and disable directory listing.",
    "robots.txt":
        "Review robots.txt and remove sensitive paths or protect them by auth.",
    "open_ports":
        "Restrict unneeded ports using a firewall; prefer allowlists and TLS.",
    "tls_expired":
        "Renew TLS/SSL certificates before expiration to maintain secure connections.",
    "tls_insecure":
        "Use modern TLS versions (1.2 or higher) and disable weak ciphers."
}

SECURITY_HEADER_SET = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
]

def safe_join(base, href):
    try:
        return urljoin(base, href)
    except Exception:
        return href

def scrape_static(url, user_agent, timeout=15):
    headers = {"User-Agent": user_agent}
    resp = requests.get(url, headers=headers, timeout=timeout)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    title = soup.title.string.strip() if soup.title and soup.title.string else "N/A"
    headings = [h.get_text(strip=True) for h in soup.find_all(["h1","h2","h3","h4","h5","h6"])]

    links = [safe_join(url, a.get("href")) for a in soup.find_all("a", href=True)]
    scripts = [safe_join(url, s.get("src")) for s in soup.find_all("script", src=True)]
    images = [safe_join(url, i.get("src")) for i in soup.find_all("img", src=True)]
    iframes = [safe_join(url, f.get("src")) for f in soup.find_all("iframe", src=True)]

    meta = {}
    for m in soup.find_all("meta"):
        name = m.get("name") or m.get("property") or m.get("http-equiv")
        content = m.get("content")
        if name and content:
            meta[name] = content

    return {
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "title": title,
        "headings": headings,
        "links": links,
        "scripts": scripts,
        "images": images,
        "iframes": iframes,
        "meta": meta,
        "html": resp.text
    }

def missing_security_headers(headers):
    lower = {k.lower(): v for k, v in headers.items()}
    return [h for h in SECURITY_HEADER_SET if h not in lower]

def check_common_paths(base_url, user_agent, timeout=6):
    found = []
    hdr = {"User-Agent": user_agent}
    for p in COMMON_ADMIN_PATHS:
        test = base_url.rstrip("/") + p
        try:
            r = requests.get(test, headers=hdr, timeout=timeout, allow_redirects=True)
            if r.status_code < 400:
                found.append({"url": test, "status": r.status_code})
        except Exception:
            pass
    return found

def check_git_exposed(base_url, user_agent, timeout=6):
    try:
        r = requests.get(urljoin(base_url, "/.git/HEAD"), headers={"User-Agent": user_agent}, timeout=timeout)
        if r.status_code == 200 and "ref:" in r.text:
            return True, r.text.strip()
    except Exception:
        pass
    return False, ""

def check_robots(base_url, user_agent, timeout=6):
    try:
        r = requests.get(urljoin(base_url, "/robots.txt"), headers={"User-Agent": user_agent}, timeout=timeout)
        if r.status_code == 200 and r.text.strip():
            return r.text.strip()
    except Exception:
        pass
    return None

def parse_tls_certificate(hostname, port=443, timeout=6):
    info = {"valid": False, "expired": False, "subject": "", "issuer": "", "not_before": "", "not_after": ""}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                info["subject"] = str(cert.subject.rfc4514_string())
                info["issuer"] = str(cert.issuer.rfc4514_string())
                info["not_before"] = str(cert.not_valid_before)
                info["not_after"] = str(cert.not_valid_after)
                info["valid"] = True

                now = datetime.utcnow()
                if cert.not_valid_after < now:
                    info["expired"] = True
                else:
                    info["expired"] = False

                # check TLS version
                info["tls_version"] = ssock.version()
    except Exception as e:
        info["error"] = str(e)
    return info

def tcp_connect(host, port, timeout=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def scan_ports(host, start, end, timeout=0.6, max_threads=200):
    if start > end:
        start, end = end, start
    open_ports = []
    lock = threading.Lock()
    ports = list(range(start, end + 1))
    idx = {"i": 0}

    def worker():
        while True:
            with lock:
                if idx["i"] >= len(ports):
                    return
                p = ports[idx["i"]]
                idx["i"] += 1
            if tcp_connect(host, p, timeout=timeout):
                with lock:
                    open_ports.append(p)

    threads = []
    for _ in range(min(max_threads, len(ports))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    open_ports.sort()
    return open_ports

def generate_recommendations(vuln, open_ports):
    recs = []
    for h in vuln.get("missing_headers", []):
        if h in REMEDIATION_GUIDE:
            recs.append(REMEDIATION_GUIDE[h])
    if vuln.get("git_exposed", {}).get("exposed"):
        recs.append(REMEDIATION_GUIDE["git_exposed"])
    if vuln.get("common_paths"):
        recs.append(REMEDIATION_GUIDE["common_paths"])
    if vuln.get("robots_txt"):
        recs.append(REMEDIATION_GUIDE["robots.txt"])
    if open_ports:
        recs.append(REMEDIATION_GUIDE["open_ports"])
    tls = vuln.get("tls_info", {})
    if tls.get("expired"):
        recs.append(REMEDIATION_GUIDE["tls_expired"])
    if tls.get("tls_version") and tls["tls_version"] not in ("TLSv1.2", "TLSv1.3"):
        recs.append(REMEDIATION_GUIDE["tls_insecure"])
    if not recs:
        recs.append("No immediate remediation items detected.")
    return recs

class DeepInspectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1100x850")

        self.user_agent = tk.StringVar(value="Mozilla/5.0")
        self.port_range = tk.StringVar(value="1-1024")

        self.current_result = {}
        self.current_vuln = {}
        self.current_ports = []

        self._build_controls()
        self._build_tabs()
        self._build_status()

    def _build_controls(self):
        frame = ttk.Frame(self.root)
        frame.pack(fill=tk.X, padx=10, pady=8)

        ttk.Label(frame, text="Target (URL or host):").grid(row=0, column=0, sticky=tk.W)
        self.target_entry = ttk.Entry(frame, width=70)
        self.target_entry.grid(row=0, column=1, padx=6)
        ttk.Button(frame, text="Inspect", command=self.on_inspect).grid(row=0, column=2, padx=6)
        ttk.Button(frame, text="Vulnerability Check", command=self.on_vuln_scan).grid(row=0, column=3, padx=6)
        ttk.Button(frame, text="Scan Ports", command=self.on_port_scan).grid(row=0, column=4, padx=6)
        ttk.Button(frame, text="Export JSON", command=self.on_export).grid(row=0, column=5, padx=6)

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=10, pady=8)

        def add_tab(name):
            frame = ttk.Frame(self.notebook)
            box = scrolledtext.ScrolledText(frame, wrap=tk.WORD)
            box.pack(expand=True, fill=tk.BOTH)
            self.notebook.add(frame, text=name)
            return box

        self.tabs = {
            "Overview": add_tab("Overview"),
            "Headers": add_tab("Headers"),
            "HTML": add_tab("HTML"),
            "Links": add_tab("Links"),
            "Scripts": add_tab("Scripts"),
            "Images": add_tab("Images"),
            "Iframes": add_tab("Iframes"),
            "Metadata": add_tab("Metadata"),
            "Vulnerabilities": add_tab("Vulnerabilities"),
            "Recommendations": add_tab("Recommendations"),
            "Ports": add_tab("Ports")
        }

    def _build_status(self):
        s = ttk.Frame(self.root)
        s.pack(fill=tk.X, padx=10, pady=8)
        self.status_lbl = ttk.Label(s, text="Ready")
        self.status_lbl.pack(side=tk.LEFT)
        self.progress = ttk.Progressbar(s, mode="indeterminate")
        self.progress.pack(side=tk.RIGHT, fill=tk.X, expand=True)

    def on_inspect(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter target")
            return
        if not target.startswith("http"):
            target = "http://" + target
        for box in self.tabs.values():
            box.delete("1.0", tk.END)
        self.status_lbl.config(text="Inspecting...")
        self.progress.start(10)
        threading.Thread(target=self._inspect_thread, args=(target,), daemon=True).start()

    def _inspect_thread(self, target):
        try:
            ua = self.user_agent.get()
            data = scrape_static(target, ua)
            self.current_result = data
            self.root.after(0, lambda: self._fill_tabs(target, data))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Inspect", str(e)))
            self._finish()

    def _fill_tabs(self, target, data):
        self.tabs["Overview"].insert(tk.END, "Target: %s\nStatus: %s\nTitle: %s\n" %
                                     (target, data.get("status_code"), data.get("title")))
        for k, v in data.get("headers", {}).items():
            self.tabs["Headers"].insert(tk.END, "%s: %s\n" % (k, v))
        self.tabs["HTML"].insert(tk.END, data.get("html", "")[:50000])
        for key in ["Links", "Scripts", "Images", "Iframes"]:
            for item in data.get(key.lower(), []):
                self.tabs[key].insert(tk.END, item + "\n")
        for k, v in data.get("meta", {}).items():
            self.tabs["Metadata"].insert(tk.END, "%s: %s\n" % (k, v))
        self._finish()

    def on_vuln_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter target")
            return
        if not target.startswith("http"):
            target = "http://" + target
        self.tabs["Vulnerabilities"].delete("1.0", tk.END)
        self.tabs["Recommendations"].delete("1.0", tk.END)
        self.status_lbl.config(text="Scanning vulnerabilities...")
        self.progress.start(10)
        threading.Thread(target=self._vuln_thread, args=(target,), daemon=True).start()

    def _vuln_thread(self, target):
        try:
            ua = self.user_agent.get()
            parsed = urlparse(target)
            base = parsed.scheme + "://" + parsed.netloc
            headers = self.current_result.get("headers", {}) if self.current_result else {}
            vuln = {
                "missing_headers": missing_security_headers(headers),
                "common_paths": check_common_paths(base, ua),
                "git_exposed": {},
                "robots_txt": check_robots(base, ua),
                "tls_info": parse_tls_certificate(parsed.hostname)
            }
            exposed, head = check_git_exposed(base, ua)
            vuln["git_exposed"] = {"exposed": exposed, "head": head}
            self.current_vuln = vuln
            recs = generate_recommendations(vuln, self.current_ports)
            self.root.after(0, lambda: self._fill_vuln_tabs(vuln, recs))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Vuln", str(e)))
            self._finish()

    def _fill_vuln_tabs(self, vuln, recs):
        box = self.tabs["Vulnerabilities"]
        box.insert(tk.END, "Missing Headers:\n")
        for h in vuln.get("missing_headers", []):
            box.insert(tk.END, "- %s\n" % h)
        box.insert(tk.END, "\nTLS Info:\n" + json.dumps(vuln.get("tls_info", {}), indent=2)[:2000] + "\n")
        self.tabs["Recommendations"].insert(tk.END, "\n".join(["- " + r for r in recs]))
        self._finish()

    def on_port_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter target")
            return
        host = urlparse(target).hostname if target.startswith("http") else target
        self.tabs["Ports"].delete("1.0", tk.END)
        self.status_lbl.config(text="Scanning ports...")
        self.progress.start(10)
        try:
            pr = self.port_range.get()
            a, b = [int(x) for x in pr.split("-")]
        except Exception:
            a, b = 1, 1024
        threading.Thread(target=self._port_thread, args=(host, a, b), daemon=True).start()

    def _port_thread(self, host, a, b):
        try:
            resolved = socket.gethostbyname(host)
            open_ports = scan_ports(resolved, a, b)
            self.current_ports = open_ports
            self.root.after(0, lambda: self._fill_ports(host, resolved, open_ports))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Ports", str(e)))
            self._finish()

    def _fill_ports(self, host, resolved, ports):
        b = self.tabs["Ports"]
        b.insert(tk.END, "Host: %s (%s)\n" % (host, resolved))
        if not ports:
            b.insert(tk.END, "No open ports.\n")
        else:
            b.insert(tk.END, "Open Ports:\n")
            for p in ports:
                b.insert(tk.END, "- %s\n" % p)
        self._finish()

    def on_export(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        bundle = {"static": self.current_result, "vuln": self.current_vuln, "ports": self.current_ports}
        with open(path, "w") as f:
            json.dump(bundle, f, indent=2)
        messagebox.showinfo("Export", "Saved to " + path)

    def _finish(self):
        self.progress.stop()
        self.status_lbl.config(text="Done")

def main():
    root = tk.Tk()
    app = DeepInspectorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
