import sys
import requests
import hashlib
import re
import urllib.parse
import sqlite3
import csv
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QComboBox, QPushButton, QTextEdit, QStatusBar, QProgressBar, 
    QFileDialog, QTabWidget, QFrame, QTreeWidget, QTreeWidgetItem, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QCheckBox
)
from PySide6.QtCore import QThread, Signal, Qt, QElapsedTimer
from PySide6.QtGui import QFont, QTextCursor, QPixmap, QImage, QColor

# ==========================================
# DATABASE SETUP
# ==========================================
def init_db():
    with sqlite3.connect('privacy_history.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scans
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      target TEXT,
                      timestamp TEXT,
                      score INTEGER,
                      exposures INTEGER)''')
        conn.commit()

def save_scan_to_db(target, score, exposures):
    with sqlite3.connect('privacy_history.db') as conn:
        c = conn.cursor()
        c.execute("INSERT INTO scans (target, timestamp, score, exposures) VALUES (?, ?, ?, ?)",
                  (target, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), score, exposures))
        conn.commit()

def fetch_history():
    with sqlite3.connect('privacy_history.db') as conn:
        c = conn.cursor()
        c.execute("SELECT timestamp, target, score, exposures FROM scans ORDER BY timestamp DESC LIMIT 100")
        return c.fetchall()

def clear_history_db():
    with sqlite3.connect('privacy_history.db') as conn:
        c = conn.cursor()
        c.execute("DELETE FROM scans")
        conn.commit()

# ==========================================
# IP SAFETY CHECK WORKER
# ==========================================
class IPCheckWorker(QThread):
    ip_result = Signal(str, bool)

    def run(self):
        try:
            res = requests.get("https://ipinfo.io/json", timeout=5).json()
            org = res.get("org", "Unknown ISP")
            ip = res.get("ip", "Unknown")
            vpn_keywords = ["hosting", "vpn", "datacenter", "cloud", "server", "digitalocean", "amazon", "aws", "m247", "ovh", "leaseweb"]
            is_vpn = any(keyword in org.lower() for keyword in vpn_keywords)
            if is_vpn:
                self.ip_result.emit(f"🟢 IP Safety Check Passed: {ip} ({org}). VPN/Proxy detected.", True)
            else:
                self.ip_result.emit(f"🔴 WARNING: Your real IP ({ip}) is exposed ({org}). Use a VPN before scanning!", False)
        except Exception:
            self.ip_result.emit("⚠️ Could not verify IP safety (ipinfo.io blocked).", True)

# ==========================================
# OSINT WORKER THREAD
# ==========================================
class OsintWorker(QThread):
    update_signal = Signal(str, str)
    progress_signal = Signal(int, int)
    status_signal = Signal(str)
    avatar_signal = Signal(bytes, str, str, str)
    task_signal = Signal(str, str)
    finished_signal = Signal(dict, float, int)

    def __init__(self, target, use_perms=False):
        super().__init__()
        self.target = target.strip()
        self.is_email = "@" in self.target
        self.is_phone = re.match(r'^\+?[\d\s\-]{7,15}$', self.target)
        self.use_perms = use_perms
        self.is_cancelled = False  # Flag for cancellation
        self.targets_to_scan = []
        self.found_platforms = []
        self.archived_platforms = []
        self.total_checks_made = 0
        self.extracted_name = None
        self.is_edu = False
        self.is_custom_domain = False
        self.is_gov_mil = False
        self.domain_name = None
        self.analytics = {
            "score": 100,
            "exposures": 0,
            "intel_risks": [],
            "categories": {"Developer": 0, "Social": 0, "Media": 0, "Other": 0}
        }
        self.lock = threading.Lock()
        
        # Use a session for connection pooling (faster requests)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def run(self):
        self.timer = QElapsedTimer()
        self.timer.start()
        
        self.update_signal.emit("results", f"<b>[INFO] Initializing deep scan for: {self.target}</b><br>")
        
        if self.is_phone:
            self.check_phone_footprint()
        elif self.is_email:
            self.analyze_email_pii()
            if not self.is_cancelled: self.fetch_avatar()
            if not self.is_cancelled: self.check_email_footprint()
        else:
            self.analyze_username_intelligence()
            if not self.is_cancelled and self.use_perms:
                self.generate_permutations()
            if not self.is_cancelled:
                self.check_username_footprint()

        if self.is_cancelled:
            self.update_signal.emit("results", "<br><b>[CANCELLED]</b> Scan aborted by user. Generating partial report...<br>")
        else:
            self.update_signal.emit("results", "<br><b>[INFO] Scan complete. Generating Action Plan...</b>")
        
        self.generate_context_report()
        self.generate_actionable_tasks()
        
        elapsed_sec = self.timer.elapsed() / 1000.0
        self.finished_signal.emit(self.analytics, elapsed_sec, self.total_checks_made)

    def generate_permutations(self):
        self.targets_to_scan.append(self.target)
        if "_" in self.target:
            base = self.target.replace("_", "")
            if base not in self.targets_to_scan: self.targets_to_scan.append(base)
            base_dot = self.target.replace("_", ".")
            if base_dot not in self.targets_to_scan: self.targets_to_scan.append(base_dot)
        elif "." in self.target:
            base = self.target.replace(".", "")
            if base not in self.targets_to_scan: self.targets_to_scan.append(base)
            base_underscore = self.target.replace(".", "_")
            if base_underscore not in self.targets_to_scan: self.targets_to_scan.append(base_underscore)
        
        if len(self.targets_to_scan) > 1:
            self.update_signal.emit("results", f'<span style="color: #0a84ff;">[PERMUTATIONS]</span> Also scanning variations: {", ".join(self.targets_to_scan[1:])}<br>')

    def check_wayback_machine(self, url):
        if self.is_cancelled: return
        try:
            api_url = f"http://archive.org/wayback/available?url={url}"
            res = self.session.get(api_url, timeout=5).json()
            if res.get("archived_snapshots", {}).get("closest", {}).get("available"):
                snapshot_url = res["archived_snapshots"]["closest"]["url"]
                self.update_signal.emit("results", f'<span style="color: #8b0000;">[ARCHIVE]</span> Permanent history found on Wayback Machine: <a href="{snapshot_url}">{snapshot_url}</a><br>')
                self.archived_platforms.append(snapshot_url)
                with self.lock:
                    self.analytics["score"] -= 5
        except Exception:
            pass

    def fetch_avatar(self):
        if self.is_cancelled: return
        self.status_signal.emit("Querying Gravatar API...")
        email_hash = hashlib.md5(self.target.lower().encode('utf-8')).hexdigest()
        avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404&s=200"
        try:
            response = self.session.get(avatar_url, timeout=5)
            if response.status_code == 200:
                self.update_signal.emit("results", f'<span style="color: #ff4c4c;">[VISUAL LEAK]</span> Public avatar image found!<br>')
                encoded_url = urllib.parse.quote(avatar_url, safe='')
                google_lens = f"https://lens.google.com/uploadbyurl?url={encoded_url}"
                yandex = f"https://yandex.com/images/search?rpt=imageview&url={encoded_url}"
                tineye = f"https://tineye.com/search/?url={encoded_url}"
                self.avatar_signal.emit(response.content, google_lens, yandex, tineye)
            else:
                self.update_signal.emit("results", f'<span style="color: #4caf50;">[SAFE]</span> No public avatar image found.<br>')
        except requests.RequestException:
            pass

    def analyze_email_pii(self):
        risks = []
        prefix = self.target.split('@')[0]
        domain = self.target.split('@')[1]
        self.domain_name = domain
        
        if re.search(r'(19|20)\d{2}', prefix):
            risks.append("Email contains a 4-digit birth year. Leaks age.")
            self.analytics["score"] -= 10
            
        if re.match(r'^\d{10}$', prefix):
            risks.append("Email prefix is a 10-digit phone number. This directly links your email to your mobile number.")
            self.analytics["score"] -= 15
            
        name_parts = re.split(r'[._\-]', prefix)
        if len(name_parts) >= 2 and all(part.isalpha() for part in name_parts[:2]):
            self.extracted_name = f"{name_parts[0]} {name_parts[1]}"
            risks.append(f"Email prefix implies real name (<b>{self.extracted_name}</b>). Data brokers can easily link this to your physical address.")
            self.analytics["score"] -= 15

        privacy_providers = ['proton.me', 'protonmail.com', 'tuta.io', 'tutamail.com', 'fastmail.com', 'skiff.com']
        common_providers = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'aol.com']
        
        if domain.lower().endswith('.mil') or domain.lower().endswith('.gov'):
            self.is_gov_mil = True
            risks.append("Government/Military (.mil/.gov) email detected. These are high-value targets for nation-state hackers and often appear in public military/gov directories.")
            self.analytics["score"] -= 20
        elif domain.lower().endswith('.edu'):
            self.is_edu = True
            risks.append("Educational (.edu) email detected. Under FERPA, university directories often publish your name, major, and email publicly.")
            self.analytics["score"] -= 15
        elif domain.lower() not in common_providers and domain.lower() not in privacy_providers:
            self.is_custom_domain = True
            risks.append(f"Custom domain ({domain}) used. WHOIS records and Corporate Registry (LLC) likely expose real name/address.")
            self.analytics["score"] -= 15
            self.status_signal.emit(f"Querying DNS/Shodan for {domain}...")
            try:
                dns_res = self.session.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=5).json()
                ips = [r.get('data', '') for r in dns_res.get('Answer', []) if r.get('type') == 1]
                if ips:
                    shodan_link = f"https://www.shodan.io/host/{ips[0]}"
                    risks.append(f"Domain resolves to IP <a href='{shodan_link}'>{ips[0]}</a>. Click to view Shodan exposed ports/services.")
            except Exception:
                pass
        elif domain.lower() in common_providers:
            risks.append(f"Using a Big Tech provider ({domain}). These providers scan and harvest your emails for ad targeting.")
            self.analytics["score"] -= 5

        if risks:
            self.analytics["intel_risks"].extend(risks)
            self.update_signal.emit("results", f'<span style="color: #ff4c4c;">[EMAIL PII]</span> Email string analysis identified metadata leaks.<br>')

    def analyze_username_intelligence(self):
        risks = []
        if re.search(r'(19|20)\d{2}', self.target):
            risks.append("Contains a potential birth year (e.g., 1995).")
            self.analytics["score"] -= 10
        if re.match(r'^[a-z]+[_\.\-][a-z]+$', self.target, re.IGNORECASE):
            risks.append("Appears to follow a 'First_Last' name pattern.")
            self.analytics["score"] -= 10

        if risks:
            self.analytics["intel_risks"].extend(risks)
            self.update_signal.emit("results", f'<span style="color: #ffa500;">[USERNAME INTEL]</span> Username pattern analysis identified potential leaks.<br>')

    def check_username_footprint(self):
        platforms = [
            ("GitHub", "https://api.github.com/users/{}", "api_status", "Developer", "https://github.com/settings/emails", "https://github.com/account/delete", "Hide emails on GitHub.", False),
            ("GitLab", "https://gitlab.com/api/v4/users?username={}", "api_json_empty", "Developer", "https://gitlab.com/-/profile", "https://gitlab.com/profile/account/delete_account", "Hide profile info on GitLab.", False),
            ("Reddit", "https://www.reddit.com/user/{}/about.json", "api_status", "Social", "https://www.reddit.com/settings/privacy", "https://www.reddit.com/account/delete", "Turn off search engine indexing on Reddit.", True),
            ("Pastebin", "https://pastebin.com/u/{}", "api_status", "Developer", "https://pastebin.com/settings", "https://pastebin.com/account", "Delete sensitive pastes.", True),
            ("Rentry", "https://rentry.co/{}", "api_status", "Developer", "https://rentry.co", "https://rentry.co", "Delete sensitive rentry pastes.", True),
            ("Keybase", "https://keybase.io/{}", "api_status", "Developer", "https://keybase.io/account", "https://keybase.io/account/delete_me", "Unlink crypto keys and delete Keybase profile.", True),
            ("Medium", "https://medium.com/@{}", "api_status", "Media", "https://medium.com/me/settings/security", "https://medium.com/me/settings/deactivate", "Deactivate Medium account.", True),
            ("Flickr", "https://www.flickr.com/people/{}", "api_status", "Media", "https://www.flickr.com/account/privacy", "https://www.flickr.com/account/delete", "Hide EXIF data on Flickr.", True),
            ("SoundCloud", "https://soundcloud.com/{}", "api_status", "Media", "https://soundcloud.com/settings", "https://soundcloud.com/settings/account/delete", "Remove real name from SoundCloud bio.", True),
            ("Roblox", "https://www.roblox.com/user.aspx?username={}", "api_status", "Other", "https://www.roblox.com/my/account/settings", "https://www.roblox.com/my/account/settings", "Hide Roblox profile from search engines.", True),
            ("HackerNews", "https://hacker-news.firebaseio.com/v0/user/{}.json", "hn_api", "Social", "https://news.ycombinator.com", "https://news.ycombinator.com", "Delete sensitive comments on HackerNews.", True),
            ("NPM Registry", "https://registry.npmjs.org/-/user/org.couchdb.user:{}", "api_status", "Developer", "https://www.npmjs.com/settings/{}/profile", "https://www.npmjs.com/settings/{}/profile", "Hide email on NPM profile.", True),
        ]

        standard_sites = [
            ("Twitter/X", "https://twitter.com/{}", "Social", "https://twitter.com/settings/privacy_and_safety", "https://x.com/settings/deactivate", "Protect your tweets.", True),
            ("Instagram", "https://instagram.com/{}", "Social", "https://www.instagram.com/accounts/privacy_and_security/", "https://www.instagram.com/accounts/remove/request/permanent/", "Set Instagram to private.", True),
            ("TikTok", "https://tiktok.com/@{}", "Social", "https://www.tiktok.com/settings/privacy", "https://www.tiktok.com/setting/focus-on-privacy", "Set TikTok to private.", True),
            ("Steam", "https://steamcommunity.com/id/{}", "Other", "https://steamcommunity.com/my/edit/settings", "https://store.steampowered.com/account/removal", "Set Steam profile to Private.", True),
            ("Bluesky", "https://bsky.app/profile/{}", "Social", "https://bsky.app/settings", "https://bsky.app/settings", "Hide Bluesky profile from public indexing.", True),
            ("Mastodon", "https://mastodon.social/@{}", "Social", "https://mastodon.social/settings/preferences", "https://mastodon.social/settings/preferences", "Lock Mastodon account (Require followers approval).", True),
        ]

        all_checks = []
        for t in self.targets_to_scan:
            for p in platforms:
                url = p[1].format(t)
                settings_url = p[4].format(t) if "{}" in p[4] else p[4]
                delete_url = p[5].format(t) if "{}" in p[5] else p[5]
                all_checks.append((p[0], url, p[2], p[3], settings_url, delete_url, p[6], p[7]))
            for s in standard_sites:
                all_checks.append((s[0], s[1].format(t), "scrape", s[2], s[3], s[4], s[5], s[6]))

        self.total_checks_made = len(all_checks)
        self.progress_signal.emit(0, self.total_checks_made)
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.process_platform, check): check for check in all_checks}
            for count, future in enumerate(as_completed(futures)):
                if self.is_cancelled:
                    break
                future.result()
                self.progress_signal.emit(count + 1, self.total_checks_made)

        if self.is_cancelled:
            return  # Skip developer intel and wayback if cancelled

        if any(p[0] == "GitHub" for p in self.found_platforms):
            self.check_developer_intel(self.target)

        if self.found_platforms:
            self.update_signal.emit("results", "<br><b>[INFO] Checking Internet Archive for historical exposures...</b><br>")
            for name, url, _, _, _, _, _ in self.found_platforms:
                if self.is_cancelled: break
                self.status_signal.emit(f"Querying Wayback Machine for {name}...")
                self.check_wayback_machine(url)

    def check_phone_footprint(self):
        self.status_signal.emit("Analyzing phone number exposure...")
        self.update_signal.emit("results", "<b>[INFO] Phone number detected. Generating messaging app footprint...</b><br>")
        self.progress_signal.emit(0, 1)
        
        clean_phone = re.sub(r'[^\d]', '', self.target)
        
        wa_link = f"https://wa.me/{clean_phone}"
        tg_link = f"https://t.me/+{clean_phone}"
        truecaller_link = f"https://www.truecaller.com/search/{clean_phone}"
        
        self.update_signal.emit("results", f'<span style="color: #ffa500;">[PHONE OSINT]</span> Click to check if your number has public profiles on messaging apps:<br>')
        self.update_signal.emit("results", f'<ul><li><a href="{wa_link}">Check WhatsApp Profile</a></li><li><a href="{tg_link}">Check Telegram Profile</a></li><li><a href="{truecaller_link}">Check Truecaller (See what name others saved you as)</a></li></ul>')
        
        self.analytics["intel_risks"].append("Phone numbers are highly sensitive. They are often used for SIM-swapping attacks and cross-platform tracking.")
        self.analytics["score"] -= 20
        self.progress_signal.emit(1, 1)
        self.total_checks_made = 1

    def check_developer_intel(self, username):
        self.update_signal.emit("results", "<br><b>[DEV INTEL] Running Developer Metadata Exploit Checks...</b><br>")
        
        self.status_signal.emit("Querying GitHub Gists API...")
        try:
            res = self.session.get(f"https://api.github.com/users/{username}/gists", timeout=5)
            if res.status_code == 403:
                self.update_signal.emit("results", f'<span style="color: #ffa500;">[RATE LIMIT]</span> GitHub API rate limit exceeded. Skipping Gists check.<br>')
            elif res.status_code == 200:
                data = res.json()
                if len(data) > 0:
                    gist_count = len(data)
                    self.update_signal.emit("results", f'<span style="color: #ff4c4c;">[DEV LEAK]</span> Found {gist_count} public GitHub Gists. These often contain leaked API keys or .env files: <a href="https://gist.github.com/{username}">View Gists</a><br>')
                    self.task_signal.emit("Developer Threats", f"<b>Audit GitHub Gists:</b> You have {gist_count} public gists. Delete or privatize any containing sensitive code, API keys, or configurations.")
        except Exception: pass

        self.status_signal.emit("Querying GitHub SSH Keys API...")
        try:
            res = self.session.get(f"https://api.github.com/users/{username}/keys", timeout=5)
            if res.status_code == 403:
                self.update_signal.emit("results", f'<span style="color: #ffa500;">[RATE LIMIT]</span> GitHub API rate limit exceeded. Skipping SSH Keys check.<br>')
            elif res.status_code == 200:
                keys = res.json()
                if len(keys) > 0:
                    self.update_signal.emit("results", f'<span style="color: #ffa500;">[DEV LEAK]</span> Found {len(keys)} public SSH keys on GitHub.')
                    for key in keys:
                        if "@" in key.get("title", ""):
                            email_in_key = key["title"]
                            self.update_signal.emit("results", f'<span style="color: #ff4c4c;">[CRITICAL LEAK]</span> SSH Key title contains an email: {email_in_key}<br>')
                            self.analytics["score"] -= 15
                            self.analytics["intel_risks"].append(f"Your GitHub SSH Key title explicitly leaks your email ({email_in_key}).")
                            self.task_signal.emit("Developer Threats", f"<b>Fix SSH Key Leak:</b> Remove the email ({email_in_key}) from your SSH key title on GitHub and rotate the key if it's sensitive.")
        except Exception: pass

    def process_platform(self, check_data):
        if self.is_cancelled:
            return
        name, url, check_type, category, settings_url, delete_url, advice, is_indexed = check_data
        self.status_signal.emit(f"Querying {name}...")
        try:
            response = self.session.get(url, timeout=5)
            
            found = False
            if check_type == "api_status" and response.status_code == 200:
                if name == "GitHub" and response.status_code == 403:
                    self.update_signal.emit("results", f'<span style="color: #ffa500;">[RATE LIMIT]</span> GitHub API rate limit exceeded.<br>')
                if name == "Roblox" and "Page not found" in response.text:
                    found = False
                else:
                    found = True
            elif check_type == "hn_api" and response.status_code == 200 and response.text.strip() != "null":
                found = True
            elif check_type == "api_json_empty" and response.status_code == 200:
                try:
                    if response.json() != []:
                        found = True
                except ValueError:
                    found = False  # JSON Decode error
            elif check_type == "scrape" and response.status_code == 200:
                if name == "Steam" and "The specified profile could not be found" in response.text:
                    found = False
                elif name == "Instagram" and "Sorry, this page isn't available." in response.text:
                    found = False
                elif name == "TikTok" and "Couldn't find this account" in response.text:
                    found = False
                else:
                    found = True

            if found:
                self.update_signal.emit("results", f'<span style="color: #ff4c4c;">[FOUND]</span> {name}: <a href="{url}">{url}</a><br>')
                with self.lock:
                    self.found_platforms.append((name, url, settings_url, delete_url, advice, category, is_indexed))
                    self.analytics["exposures"] += 1
                    self.analytics["score"] -= 10
                    self.analytics["categories"][category] += 1
            else:
                if self.target in url:
                    self.update_signal.emit("results", f'<span style="color: #4caf50;">[SAFE]</span> Not found on {name}.<br>')
        except requests.RequestException:
            pass

    def check_email_footprint(self):
        self.status_signal.emit("Checking breach databases...")
        self.update_signal.emit("results", "<b>[INFO] Checking email public exposure...</b><br>")
        self.progress_signal.emit(0, 1)
        hibp_link = f"https://haveibeenpwned.com/account/{self.target}"
        self.update_signal.emit("results", f'For a comprehensive data breach check, <a href="{hibp_link}">click here to search HaveIBeenPwned for {self.target}</a>.<br>')
        self.progress_signal.emit(1, 1)
        self.total_checks_made = 1

    def generate_context_report(self):
        report_html = ""
        score = max(0, self.analytics["score"])
        
        if score >= 80: risk_level = "<span style='color:#4caf50; font-weight:bold;'>Low Risk</span>"
        elif score >= 50: risk_level = "<span style='color:#ffa500; font-weight:bold;'>Medium Risk</span>"
        else: risk_level = "<span style='color:#ff4c4c; font-weight:bold;'>High Risk</span>"

        report_html += f"<h2>🎯 Privacy Risk Assessment</h2>"
        report_html += f"<p><b>Overall Score:</b> {score}/100 ({risk_level})<br><b>Total Exposures Found:</b> {self.analytics['exposures']}</p>"
        
        cats = self.analytics["categories"]
        report_html += f"<p><b>Public Exposure Breakdown:</b><br>Developer/Tech: {cats['Developer']} | Social: {cats['Social']} | Media: {cats['Media']} | Other: {cats['Other']}</p><hr>"

        report_html += "<h3>🔍 Search Engine, Dark Web & Leak Exposure</h3><p>Click these links to see if your data is currently public on OSINT/Dark Web search engines:</p><ul>"
        dork = urllib.parse.quote(f'"{self.target}"')
        intelx_link = f"https://intelx.io/?s={dork}"
        dehashed_link = f"https://dehashed.com/search?query={dork}"
        
        report_html += f'<li><a href="https://www.google.com/search?q={dork}">Google: Exact Match Search</a></li>'
        report_html += f'<li><a href="{intelx_link}">Intelligence X: Deep Web & Leak Database Search</a></li>'
        report_html += f'<li><a href="{dehashed_link}">Dehashed: Search for Leaked Passwords & Hashes</a></li>'
        report_html += f'<li><a href="https://ahmia.fi/search/?q={dork}">Ahmia: Dark Web (.onion) Search</a></li>'
        
        if self.is_email:
            report_html += f'<li><a href="https://www.google.com/search?q={dork}+site:linkedin.com">Google: LinkedIn Email Search</a></li>'
            report_html += f'<li><a href="https://www.google.com/search?q={dork}+(filetype:txt+OR+filetype:csv)+password">Google: Credential Dump Search</a></li>'
        else:
            report_html += f'<li><a href="https://www.google.com/search?q={dork}+site:pastebin.com">Google: Pastebin Username Search</a></li>'
        report_html += "</ul><hr>"

        if self.extracted_name or self.is_email:
            report_html += "<h3>👤 Public Records, Property & People Search OSINT</h3>"
            if self.extracted_name:
                name_dork = urllib.parse.quote(f'"{self.extracted_name}"')
                report_html += f"<p>We extracted the name <b>{self.extracted_name}</b> from your email. Check these public records and data brokers:</p><ul>"
                report_html += f'<li><a href="https://www.google.com/search?q={name_dork}+(filetype:pdf+OR+filetype:docx+OR+filetype:xlsx)">Google: Search for leaked Documents (Resumes, Rosters)</a></li>'
                report_html += f'<li><a href="https://www.spokeo.com/{urllib.parse.quote(self.extracted_name)}">Spokeo: People Search</a></li>'
                report_html += f'<li><a href="https://www.truepeoplesearch.com/results?name={urllib.parse.quote(self.extracted_name)}">TruePeopleSearch: Public Records</a></li>'
                report_html += f'<li><a href="https://voterrecords.com/voters/{urllib.parse.quote(self.extracted_name)}">VoterRecords: Public Voting Registration Lookup</a></li>'
                report_html += "</ul><hr>"
                
                report_html += "<h3>🏥 Healthcare & Professional License OSINT</h3>"
                report_html += f"<p>If you are a doctor, nurse, or medical professional, your NPI (National Provider Identifier) and practice address are public:</p><ul>"
                report_html += f'<li><a href="https://npiregistry.cms.hhs.gov/registry/npi-record-view?name={urllib.parse.quote(self.extracted_name)}">NPI Registry: Lookup Medical License & Public Address</a></li>'
                report_html += "</ul><hr>"

                report_html += "<h3>🧬 Genealogy & Family Tree OSINT</h3>"
                report_html += f"<p>Genealogy sites expose your mother's maiden name, exact birth dates, and family relationships (classic security questions):</p><ul>"
                report_html += f'<li><a href="https://www.google.com/search?q={name_dork}+site:findagrave.com">Google: FindAGrave Records</a></li>'
                report_html += f'<li><a href="https://www.google.com/search?q={name_dork}+site:ancestry.com">Google: Ancestry Family Trees</a></li>'
                report_html += f'<li><a href="https://www.google.com/search?q={name_dork}+site:familysearch.org">Google: FamilySearch Records</a></li>'
                report_html += "</ul><hr>"

                report_html += "<h3>✈️ Aviation, Vehicle & Movement OSINT</h3>"
                report_html += f"<p>If you own an aircraft or vehicle, your physical home address is likely tied to public registries:</p><ul>"
                report_html += f'<li><a href="https://www.google.com/search?q={name_dork}+site:faa.gov">Google: FAA Pilot/Airmen Registry Records</a></li>'
                report_html += f'<li><a href="https://flightaware.com/resources/search?q={name_dork}">FlightAware: Search for Aircraft/Tail Numbers tied to your name</a></li>'
                report_html += "</ul><hr>"

                report_html += "<h3>⚖️ Court Records & Legal Filings OSINT</h3>"
                report_html += f"<p>Check if your name is tied to public federal or local court documents (bankruptcies, lawsuits, criminal records):</p><ul>"
                report_html += f'<li><a href="https://www.google.com/search?q={name_dork}+site:uscourts.gov">Google: Federal Court Records (uscourts.gov)</a></li>'
                report_html += f'<li><a href="https://pcl.uscourts.gov/pcl/FindParty.jsp">PACER: Federal Court Party Search (Requires Account)</a></li>'
                report_html += "</ul><hr>"

            if self.is_gov_mil:
                report_html += "<h3>🏛️ Government & Military Infrastructure Exposure</h3>"
                report_html += f"<p>Your .mil or .gov email is a high-value target. Check for leaked military rosters or government directories:</p><ul>"
                report_html += f'<li><a href="https://www.google.com/search?q={dork}+(filetype:pdf+OR+filetype:xlsx)">Google: Search for Government Rosters/Directories containing your email</a></li>'
                report_html += "</ul><hr>"
            
            if self.is_edu:
                report_html += "<h3>🎓 Educational & University Infrastructure Exposure</h3>"
                report_html += f"<p>Your .edu email is tied to a university. Student directories are often public:</p><ul>"
                report_html += f'<li><a href="https://www.google.com/search?q={dork}+(site:edu+OR+site:edu filetype:pdf)">Google: Search for University Profiles/Rosters containing your email</a></li>'
                report_html += "</ul><hr>"
            
            if self.is_custom_domain:
                domain = self.domain_name
                report_html += "<h3>🏢 Corporate/Group Infrastructure & Business Entity Exposure</h3>"
                report_html += f"<p>If this email belongs to a company/group, check for leaked internal documents & registered business names:</p><ul>"
                report_html += f'<li><a href="https://www.google.com/search?q=site:trello.com+"{domain}">Google: Public Trello Boards for {domain}</a></li>'
                report_html += f'<li><a href="https://www.google.com/search?q=site:atlassian.net+"{domain}">Google: Public Jira/Confluence for {domain}</a></li>'
                report_html += f'<li><a href="https://www.google.com/search?q=site:s3.amazonaws.com+"{domain}">Google: Open AWS S3 Buckets for {domain}</a></li>'
                report_html += f'<li><a href="https://github.com/search?q=%22{domain}%22+password&type=code">GitHub: Search Code for Leaked Passwords tied to {domain}</a></li>'
                report_html += f'<li><a href="https://opencorporates.com/companies?q={domain.split('.')[0]}">OpenCorporates: Search for registered LLC/Corp names matching {domain}</a></li>'
                report_html += f'<li><a href="https://www.google.com/search?q=site:linkedin.com/in+"{domain}">Google: LinkedIn Employee Roster for {domain}</a></li>'
                report_html += "</ul><hr>"

        report_html += "<h3>💳 Payment App & Transaction OSINT</h3>"
        report_html += f"<p>Public transactions on Venmo/CashApp are heavily scraped by OSINT investigators to map social graphs:</p><ul>"
        report_html += f'<li><a href="https://www.google.com/search?q={dork}+site:venmo.com">Google: Search for Public Venmo Profile/Transactions</a></li>'
        report_html += f'<li><a href="https://www.google.com/search?q={dork}+site:cash.app">Google: Search for Public CashApp Profile</a></li>'
        report_html += "</ul><hr>"

        report_html += "<h3>₿ Cryptocurrency Wallet OSINT</h3>"
        report_html += f"<p>If you posted a crypto wallet address tied to your username, your entire transaction history is public:</p><ul>"
        report_html += f'<li><a href="https://www.google.com/search?q={dork}+site:bitcointalk.org">Google: BitcoinTalk Forum Posts (Often contain Wallet Addresses)</a></li>'
        report_html += "</ul><hr>"

        if self.analytics["intel_risks"]:
            report_html += "<h3>🧠 Identity Intelligence Alerts</h3><ul>"
            for risk in self.analytics["intel_risks"]:
                report_html += f"<li>{risk}</li>"
            report_html += "</ul><hr>"
        
        self.update_signal.emit("advice_context", report_html)

    def generate_actionable_tasks(self):
        found_names = [p[0] for p in self.found_platforms]

        if "GitHub" in found_names or "GitLab" in found_names or "Pastebin" in found_names or "Rentry" in found_names or "NPM Registry" in found_names:
            self.task_signal.emit("Developer Threats", "<b>Use BFG Repo-Cleaner</b> to scrub sensitive data (passwords, keys) from git commit history.")
            self.task_signal.emit("Developer Threats", "<b>Audit all repositories</b> for accidentally committed <b>.env</b> files or API keys.")
            self.task_signal.emit("Developer Threats", "<b>Rotate any API keys/secrets</b> that may have been pushed to GitHub/Pastebin/Rentry/NPM.")

        if self.is_email and any("WHOIS" in risk for risk in self.analytics["intel_risks"]):
            self.task_signal.emit("Physical Address & Domain", "<b>Domain WHOIS Privacy:</b> Enable WHOIS privacy protection at your domain registrar. Note that historical WHOIS records (containing your real name/address) are permanent; request removal from <a href='https://whoisxmlapi.com/opt-out'>WhoisXMLAPI Opt-Out</a>.")

        if self.is_gov_mil:
            self.task_signal.emit("Government/Military Privacy", "<b>OPSEC Review:</b> Ensure you are not reusing this .mil/.gov password on civilian sites. If breached, it can lead to spear-phishing or physical security threats.")
            self.task_signal.emit("Government/Military Privacy", "<b>Public Roster Removal:</b> Search for your name on public unit rosters or PDFs. If found, contact your unit's S-2/S-6 (Security/IT) to request redaction from public web portals.")

        if self.is_custom_domain:
            self.task_signal.emit("Business Entity Privacy", "<b>LLC/Corporate Privacy:</b> If you registered an LLC, your name and address are public via the Secretary of State. Use a <b>Registered Agent Service</b> (like Northwest Registered Agent) to shield your name on future filings.")
            self.task_signal.emit("Business Entity Privacy", "<b>LinkedIn Corporate Visibility:</b> If this is a company email, ensure employee LinkedIn profiles do not leak internal infrastructure details in their job descriptions.")
        
        if self.is_edu:
            self.task_signal.emit("Educational Privacy (FERPA)", "<b>Invoke FERPA Opt-Out:</b> Contact your university's Registrar Office immediately and request to opt out of 'Directory Information' to hide your name and email from public university directories.")

        if self.extracted_name:
            self.task_signal.emit("Public Records & Brokers", f"<b>Data Broker Opt-Out:</b> Your name ({self.extracted_name}) is exposed. Submit opt-outs to <a href='https://www.spokeo.com/optout'>Spokeo</a>, <a href='https://www.whitepages.com/suppression_requests'>Whitepages</a>, and <a href='https://www.truepeoplesearch.com/removal'>TruePeopleSearch</a>.")
            self.task_signal.emit("Public Records & Brokers", "<b>Voter Record Privacy:</b> If your voter registration is public, contact your local county election office or state Secretary of State to request confidentiality status.")
            self.task_signal.emit("Public Records & Brokers", "<b>Google Results Removal:</b> Use the <a href='https://support.google.com/websearch/troubleshooter/9680840'>Google Removal Tool</a> to request deletion of exposed sensitive docs (resumes, rosters) from search results.")

            self.task_signal.emit("Healthcare & Medical Privacy", "<b>NPI Address Privacy:</b> If you are a medical professional, ensure your NPI registry address is set to your practice/clinic, NOT your home address. If your home address is public, submit an update to the NPPES system immediately.")

            self.task_signal.emit("Genealogy & Family Privacy", "<b>Family Tree Removal:</b> Genealogy sites expose your mother's maiden name. Request removal of your data from <a href='https://www.findagrave.com/memorial/management'>FindAGrave</a> and <a href='https://support.ancestry.com/s/article/Requesting-Account-or-Data-Deletion'>Ancestry.com</a>.")
            self.task_signal.emit("Genealogy & Family Privacy", "<b>Security Questions:</b> Because your mother's maiden name is likely public, change all bank and email security questions to fake answers stored in a password manager.")

            self.task_signal.emit("Aviation & Vehicle Privacy", "<b>FAA Registry Privacy:</b> If you own an aircraft, your name and home address are public on the FAA Registry. Consider registering the aircraft under an LLC (with a Registered Agent) rather than your own name.")
            self.task_signal.emit("Aviation & Vehicle Privacy", "<b>ALPR (License Plate) Opt-Out:</b> If your neighborhood uses Flock Safety cameras, you can request your vehicle's license plate be added to the local system's 'allowlist' or request data deletion to avoid tracking your movements.")

            self.task_signal.emit("Court & Legal Records", "<b>Court Record Redaction:</b> If you are involved in a civil or criminal case, work with your attorney to file a motion to redact sensitive personal identifiers (like home addresses or SSNs) from publicly accessible PACER and local court files.")

        if self.is_phone:
            self.task_signal.emit("Critical Exposures", "<b>Phone Number Aliasing:</b> Stop using your real phone number for signups. Use <b>Google Voice</b> or <b>MySudo</b> to generate secondary numbers.")
            self.task_signal.emit("Critical Exposures", "<b>Truecaller Deregistration:</b> If your name is public on Truecaller, <a href='https://www.truecaller.com/unlisting'>unlist your number</a> immediately.")
            self.task_signal.emit("Critical Exposures", "<b>Telegram/WhatsApp Privacy:</b> Set your phone number visibility to 'Nobody' in the privacy settings of both apps.")

        self.task_signal.emit("Financial App Privacy", "<b>Lock Down Venmo:</b> Venmo transactions are public by default. Go to Venmo Settings -> Privacy and set Default Privacy Setting to 'Private'. Also set 'Past Transactions' to 'Private'.")
        self.task_signal.emit("Financial App Privacy", "<b>Lock Down CashApp:</b> CashApp $cashtags are public. Do not use your real name or birth year as your $cashtag. Consider unlinking your main bank account and using a secondary debit card.")

        self.task_signal.emit("Cryptocurrency Privacy", "<b>Wallet Linkability:</b> If you posted a Bitcoin/Ethereum wallet address tied to your username, your net worth and transactions are public. Use <b>Monero (XMR)</b> for private transactions, or use a crypto mixer/tumbler to break the link between your old and new wallets.")

        self.task_signal.emit("Physical Network Privacy", "<b>Wi-Fi SSID & Geolocation:</b> Your home router broadcasts its name (SSID) publicly. Apps like WiGLE map this to your physical address. <a href='https://wigle.net/optout'>Opt out of WiGLE</a> and change your router's SSID to something unrelated to your name.")

        for name, url, settings_url, delete_url, advice, category, is_indexed in self.found_platforms:
            index_warning = ""
            if is_indexed:
                index_warning = " <b>(WARNING: This site is heavily indexed by Google. Act fast!)</b>"
            self.task_signal.emit("Critical Exposures", f"<b>[{category}] {name}</b> {advice}{index_warning} <br><i style='color:gray; font-size:10px;'>Fix: {settings_url} | Nuclear Option: {delete_url}</i>")

        if self.archived_platforms:
            for archive_url in self.archived_platforms:
                self.task_signal.emit("Historical Archives (Permanent)", f"<b>Internet Archive:</b> Your deleted/old profile is permanently archived. <a href='{archive_url}'>View Archive</a>. Submit a removal request to <a href='https://archive.org/about/terms.php'>Internet Archive</a>.")
        
        if self.is_email:
            self.task_signal.emit("Systemic Hardening", "<b>Stop using your real email.</b> Setup <b>SimpleLogin</b> or <b>DuckDuckGo Email Protection</b>.")
        self.task_signal.emit("Systemic Hardening", "<b>Setup Bitwarden password manager</b> and change exposed passwords.")
        self.task_signal.emit("Systemic Hardening", "<b>Enable 2FA</b> using <b>Aegis</b> or <b>Ente Auth</b> on all found accounts.")
        self.task_signal.emit("Systemic Hardening", "<b>Image Metadata (EXIF):</b> Always strip EXIF data from photos before uploading. Use tools like <a href='https://exifcleaner.com'>ExifCleaner</a> to remove hidden GPS coordinates from your images.")
        
        if "Twitter/X" in found_names or "Reddit" in found_names or "YouTube" in found_names:
            self.task_signal.emit("Systemic Hardening", "<b>Install LibRedirect</b> browser extension to redirect social media to privacy frontends.")

# ==========================================
# MAIN GUI WINDOW
# ==========================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Privacy Intelligence & Counter-Surveillance Suite v15")
        self.resize(1200, 950)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        header_label = QLabel("Advanced Privacy Intelligence & Counter-Surveillance Suite")
        header_font = QFont("Arial", 18, QFont.Bold)
        header_label.setFont(header_font)
        layout.addWidget(header_label)

        self.ip_banner = QLabel("Checking IP Safety...")
        self.ip_banner.setAlignment(Qt.AlignCenter)
        self.ip_banner.setStyleSheet("background-color: #444; color: white; padding: 8px; border-radius: 4px; font-weight: bold;")
        layout.addWidget(self.ip_banner)

        self.ip_worker = IPCheckWorker()
        self.ip_worker.ip_result.connect(self.update_ip_banner)
        self.ip_worker.start()

        input_layout = QHBoxLayout()
        self.target_input = QComboBox()
        self.target_input.setEditable(True)
        self.target_input.setPlaceholderText("Enter Username, Email, or Phone Number...")
        self.target_input.setToolTip("Enter the exact username, email, or phone number you want to investigate.")
        self.target_input.lineEdit().returnPressed.connect(self.start_scan)
        
        self.perm_checkbox = QCheckBox("Scan Permutations")
        self.perm_checkbox.setChecked(True)
        self.perm_checkbox.setToolTip("Also scans variations like 'user_name', 'username', and 'user.name'")

        self.scan_button = QPushButton("Run Deep Scan")
        self.scan_button.clicked.connect(self.start_scan)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.cancel_button.setEnabled(False)
        
        self.reset_button = QPushButton("Scan Another")
        self.reset_button.clicked.connect(self.reset_ui)
        self.reset_button.setEnabled(False)

        self.export_html_button = QPushButton("Export HTML")
        self.export_html_button.clicked.connect(lambda: self.export_report("html"))
        self.export_html_button.setEnabled(False)

        self.export_md_button = QPushButton("Export Markdown")
        self.export_md_button.clicked.connect(lambda: self.export_report("md"))
        self.export_md_button.setEnabled(False)

        input_layout.addWidget(self.target_input, 3)
        input_layout.addWidget(self.perm_checkbox)
        input_layout.addWidget(self.scan_button, 1)
        input_layout.addWidget(self.cancel_button, 1)
        input_layout.addWidget(self.reset_button, 1)
        input_layout.addWidget(self.export_html_button, 1)
        input_layout.addWidget(self.export_md_button, 1)
        layout.addLayout(input_layout)

        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setFormat("%p%")
        self.progress_bar.setVisible(False)
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #aaa; font-style: italic;")
        progress_layout.addWidget(self.progress_bar, 3)
        progress_layout.addWidget(self.status_label, 2)
        layout.addLayout(progress_layout)

        dashboard_layout = QHBoxLayout()
        self.score_frame = QFrame()
        score_layout = QVBoxLayout(self.score_frame)
        self.score_label = QLabel("Privacy Risk Score: N/A")
        self.score_label.setFont(QFont("Arial", 14, QFont.Bold))
        self.score_label.setAlignment(Qt.AlignCenter)
        score_layout.addWidget(self.score_label)
        self.score_frame.setVisible(False)
        
        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(80, 80)
        self.avatar_label.setAlignment(Qt.AlignCenter)
        self.avatar_label.setStyleSheet("border: 1px solid #444; background-color: #2d2d2d; color: #666;")
        self.avatar_label.setText("No Avatar\nFound")
        self.avatar_label.setVisible(False)

        dashboard_layout.addWidget(self.score_frame, 1)
        dashboard_layout.addWidget(self.avatar_label, 0)
        layout.addLayout(dashboard_layout)

        self.tabs = QTabWidget()
        
        tab1_widget = QWidget()
        tab1_layout = QVBoxLayout(tab1_widget)
        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        self.results_area.setOpenExternalLinks(True)
        tab1_layout.addWidget(self.results_area)
        self.tabs.addTab(tab1_widget, "Live Scan Console")

        tab2_widget = QWidget()
        tab2_layout = QVBoxLayout(tab2_widget)
        splitter = QSplitter(Qt.Vertical)
        self.advice_context_area = QTextEdit()
        self.advice_context_area.setReadOnly(True)
        self.advice_context_area.setOpenExternalLinks(True)
        splitter.addWidget(self.advice_context_area)

        checklist_widget = QWidget()
        checklist_layout = QVBoxLayout(checklist_widget)
        checklist_label = QLabel("🛡️ Categorized Action Plan (Check off as you complete):")
        checklist_label.setStyleSheet("font-weight: bold; padding: 5px;")
        checklist_layout.addWidget(checklist_label)
        
        self.task_tree = QTreeWidget()
        self.task_tree.setHeaderHidden(True)
        self.task_tree.setStyleSheet("QTreeWidget { background-color: #2d2d2d; color: #e0e0e0; border: 1px solid #444; } QTreeWidget::item { padding: 5px; }")
        checklist_layout.addWidget(self.task_tree)
        splitter.addWidget(checklist_widget)
        splitter.setSizes([400, 300])
        tab2_layout.addWidget(splitter)
        self.tabs.addTab(tab2_widget, "Prioritized Action Plan")

        tab3_widget = QWidget()
        tab3_layout = QVBoxLayout(tab3_widget)
        history_header_layout = QHBoxLayout()
        history_label = QLabel("📊 Scan History & Score Tracking")
        history_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        history_header_layout.addWidget(history_label)
        history_header_layout.addStretch()
        
        export_csv_btn = QPushButton("Export to CSV")
        export_csv_btn.clicked.connect(self.export_csv)
        history_header_layout.addWidget(export_csv_btn)

        clear_history_btn = QPushButton("Clear History")
        clear_history_btn.clicked.connect(self.clear_history)
        history_header_layout.addWidget(clear_history_btn)
        tab3_layout.addLayout(history_header_layout)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels(["Timestamp", "Target", "Score", "Exposures"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.setAlternatingRowColors(True)  # UI Improvement
        tab3_layout.addWidget(self.history_table)
        self.tabs.addTab(tab3_widget, "History & Tracking")

        tab4_widget = QWidget()
        tab4_layout = QVBoxLayout(tab4_widget)
        kb_label = QLabel("📚 Privacy Hardening Knowledge Base")
        kb_label.setStyleSheet("font-weight: bold; font-size: 16px; padding: 10px;")
        tab4_layout.addWidget(kb_label)
        
        self.kb_text = QTextEdit()
        self.kb_text.setReadOnly(True)
        self.kb_text.setOpenExternalLinks(True)
        self.kb_text.setHtml(self.get_knowledge_base_html())
        tab4_layout.addWidget(self.kb_text)
        self.tabs.addTab(tab4_widget, "Knowledge Base")

        layout.addWidget(self.tabs)
        self.setStatusBar(QStatusBar())
        self.load_history()

    def closeEvent(self, event):
        # Ensure threads are terminated when closing the app to prevent hanging
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.terminate()
        if hasattr(self, 'ip_worker') and self.ip_worker.isRunning():
            self.ip_worker.terminate()
        event.accept()

    def get_knowledge_base_html(self):
        return """
        <h2>How to Privatise Your Internet Presence</h2>
        <p>This guide provides actionable steps to hide your public information and secure your digital life.</p>
        <hr>
        
        <h3>1. Healthcare & Medical Privacy (NPI)</h3>
        <p>If you are a doctor, nurse, or medical professional, your NPI (National Provider Identifier) and practice address are public via CMS.</p>
        <ul>
            <li><b>NPI Address:</b> Never use your home address for your NPI registration. Always use your practice/clinic address. If your home address is currently public, log into the <a href="https://nppes.cms.hhs.gov/">NPPES</a> system and update it immediately.</li>
            <li><b>State Medical Boards:</b> State medical board websites also publish your address and license status. Check your state's board for opt-out options if you are a victim of stalking.</li>
        </ul>
        <hr>

        <h3>2. Genealogy & Family Tree Privacy</h3>
        <p>Genealogy sites expose your mother's maiden name, exact birth dates, and family relationships (classic security questions).</p>
        <ul>
            <li><b>Ancestry.com:</b> <a href="https://support.ancestry.com/s/article/Requesting-Account-or-Data-Deletion">Request Account Deletion here</a>.</li>
            <li><b>FamilySearch:</b> FamilySearch is run by the LDS Church. You can request removal of your deceased or living family records by contacting their support.</li>
            <li><b>Security Questions:</b> Because your mother's maiden name is likely public, change all bank and email security questions to fake answers (e.g., "Mother's maiden name: BlueDragon") stored in a password manager.</li>
        </ul>
        <hr>

        <h3>3. Government & Military Privacy</h3>
        <p>.mil and .gov emails are high-value targets. Unit rosters and directories are often accidentally published as PDFs.</p>
        <ul>
            <li><b>OPSEC:</b> Do not reuse .mil/.gov passwords on civilian sites. Use a unique password and hardware security key (YubiKey) if possible.</li>
            <li><b>Roster Redaction:</b> If you find your name on a public unit roster PDF, contact your unit's S-2 (Security) or S-6 (IT) to have it redacted from public web portals.</li>
        </ul>
        <hr>

        <h3>4. Cryptocurrency Privacy</h3>
        <p>Bitcoin and Ethereum are pseudonymous, not anonymous. If you posted a wallet address tied to your username, your net worth is public.</p>
        <ul>
            <li><b>Use Monero (XMR):</b> If you need digital cash privacy, use Monero. It hides sender, receiver, and amount by default.</li>
            <li><b>Mixers/Tumblers:</b> If you have linked Bitcoin, use a mixer to break the transaction graph, though be aware some exchanges block mixed coins.</li>
        </ul>
        <hr>

        <h3>5. Financial & Payment App Privacy</h3>
        <p>Payment apps like Venmo and CashApp expose your social graph and transaction history by default.</p>
        <ul>
            <li><b>Venmo:</b> Go to Settings -> Privacy. Set Default Privacy to 'Private'. Scroll down and select 'Past Transactions' -> Change to 'Private'.</li>
            <li><b>CashApp:</b> $cashtags are publicly searchable. Consider creating a new $cashtag unrelated to your real name.</li>
        </ul>
        <hr>

        <h3>6. Aviation & Vehicle Privacy (ALPRs)</h3>
        <p>If you own an aircraft or drive a car, your physical movements and home address are likely tracked.</p>
        <ul>
            <li><b>FAA Registry:</b> Aircraft ownership is public. Consider transferring ownership to an anonymous LLC with a Registered Agent.</li>
            <li><b>ALPRs (Flock Safety):</b> Automatic License Plate Readers track vehicles. If your HOA or city uses Flock cameras, you can request your license plate be added to the local system's 'allowlist' or request data deletion.</li>
        </ul>
        <hr>

        <h3>7. Court & Legal Record Redaction</h3>
        <p>If you have been involved in a lawsuit, federal and local court documents are public via PACER.</p>
        <ul>
            <li><b>Redaction:</b> Work with your attorney to ensure all sensitive personal identifiers (home address, phone, SSN, bank accounts) are redacted under Rule 5.2 of the Federal Rules of Civil Procedure.</li>
            <li><b>Expungement:</b> If you have a criminal record, consult a local attorney about expunging or sealing the record.</li>
        </ul>
        <hr>

        <h3>8. Business Entity & Corporate Privacy</h3>
        <p>If you own an LLC or business, your name and address are likely public via the Secretary of State.</p>
        <ul>
            <li><b>Registered Agents:</b> Never use your home address for business registration. Hire a Registered Agent to put their name/address on public filings instead of yours.</li>
            <li><b>Corporate Infrastructure:</b> Audit internal tools (Trello, Jira, Slack) to ensure they are not publicly accessible or indexed by Google.</li>
        </ul>
        <hr>

        <h3>9. Educational Privacy (FERPA)</h3>
        <p>If you have an .edu email, your student directory information is public unless you opt out.</p>
        <ul>
            <li><b>FERPA Opt-Out:</b> Contact your university's Registrar Office and formally request to opt out of 'Directory Information'.</li>
        </ul>
        <hr>

        <h3>10. Wi-Fi & Physical Network Privacy</h3>
        <p>Your home router constantly broadcasts its name (SSID), which can be mapped to your physical address.</p>
        <ul>
            <li><b>WiGLE Opt-Out:</b> WiGLE maps Wi-Fi networks globally. <a href="https://wigle.net/optout">Opt out here</a>.</li>
            <li><b>Change SSID:</b> Change your router's SSID to something generic that does not contain your name or apartment number.</li>
        </ul>
        <hr>

        <h3>11. Physical Address & Real Estate Privacy</h3>
        <p>Your home address is likely public via property deeds, voter registration, and historical domain WHOIS records.</p>
        <ul>
            <li><b>Historical WHOIS:</b> Request removal via <a href="https://whoisxmlapi.com/opt-out">WhoisXMLAPI Opt-Out</a>.</li>
            <li><b>Property Records:</b> Contact your local county tax assessor's office to request redaction.</li>
        </ul>
        <hr>

        <h3>12. Phone Number Privacy</h3>
        <p>Your phone number is highly vulnerable to SIM-swapping attacks.</p>
        <ul>
            <li><b>Use Aliases:</b> Use <a href="https://voice.google.com">Google Voice</a> or <a href="https://mysudo.com">MySudo</a>.</li>
            <li><b>Truecaller:</b> <a href="https://www.truecaller.com/unlisting">Unlist your number here</a>.</li>
        </ul>
        <hr>

        <h3>13. Image Metadata (EXIF) Privacy</h3>
        <p>Photos taken on smartphones often embed hidden GPS coordinates.</p>
        <ul>
            <li><b>Desktop:</b> Use <a href="https://exifcleaner.com">ExifCleaner</a> to strip metadata before uploading.</li>
        </ul>
        <hr>

        <h3>14. Public Records & Data Brokers</h3>
        <p>Data brokers scrape public records and sell your personal information online.</p>
        <ul>
            <li><b>Major Brokers:</b> Manually opt-out of <a href="https://www.spokeo.com/optout">Spokeo</a>, <a href="https://www.whitepages.com/suppression_requests">Whitepages</a>, and <a href="https://www.truepeoplesearch.com/removal">TruePeopleSearch</a>.</li>
            <li><b>Google Removals:</b> Use the <a href="https://support.google.com/websearch/troubleshooter/9680840">Google Removal Tool</a>.</li>
        </ul>
        <hr>

        <h3>15. Developer & Code Privacy</h3>
        <p>Developers are prone to leaking sensitive data via Git histories.</p>
        <ul>
            <li><b>Scrub Git History:</b> Use <a href="https://rtyley.github.io/bfg-repo-cleaner/">BFG Repo-Cleaner</a>.</li>
            <li><b>Use Environment Variables:</b> Never hardcode API keys. Use <code>.env</code> files.</li>
            <li><b>Hide Commit Emails:</b> In GitHub Settings -> Emails, check "Keep my email addresses private".</li>
        </ul>
        """

    def update_ip_banner(self, message, is_safe):
        self.ip_banner.setText(message)
        if is_safe:
            self.ip_banner.setStyleSheet("background-color: #2d5a27; color: white; padding: 8px; border-radius: 4px; font-weight: bold;")
        else:
            self.ip_banner.setStyleSheet("background-color: #8b0000; color: white; padding: 8px; border-radius: 4px; font-weight: bold;")

    def start_scan(self):
        target = self.target_input.currentText().strip()
        if not target:
            self.statusBar().showMessage("Please enter a username, email, or phone number.", 3000)
            return

        if self.target_input.findText(target) == -1:
            self.target_input.addItem(target)
        self.target_input.setCurrentText(target)

        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.export_html_button.setEnabled(False)
        self.export_md_button.setEnabled(False)
        self.reset_button.setEnabled(False)
        self.results_area.clear()
        self.advice_context_area.clear()
        self.task_tree.clear()
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Initializing...")
        self.score_frame.setVisible(False)
        self.avatar_label.setVisible(False)
        self.avatar_label.clear()
        self.avatar_label.setText("No Avatar\nFound")
        self.tabs.setCurrentIndex(0)
        self.statusBar().showMessage("Scanning... Please wait.")

        use_perms = self.perm_checkbox.isChecked()
        self.worker = OsintWorker(target, use_perms=use_perms)
        self.worker.update_signal.connect(self.update_output)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.status_signal.connect(self.update_status)
        self.worker.avatar_signal.connect(self.display_avatar)
        self.worker.task_signal.connect(self.add_task_to_tree)
        self.worker.finished_signal.connect(self.scan_complete)
        self.worker.start()

    def cancel_scan(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.is_cancelled = True
            self.status_label.setText("Cancelling scan... (waiting for active requests to finish)")
            self.cancel_button.setEnabled(False)

    def update_output(self, target_area, text):
        if target_area == "results":
            self.results_area.append(text)
            cursor = self.results_area.textCursor()
            cursor.movePosition(QTextCursor.End)
            self.results_area.setTextCursor(cursor)
        elif target_area == "advice_context":
            self.advice_context_area.setHtml(text)

    def update_progress(self, current, maximum):
        self.progress_bar.setMaximum(maximum)
        self.progress_bar.setValue(current)

    def update_status(self, text):
        self.status_label.setText(text)

    def display_avatar(self, image_bytes, google_url, yandex_url, tineye_url):
        img = QImage()
        img.loadFromData(image_bytes)
        if not img.isNull():  # Check if image data is valid
            pixmap = QPixmap.fromImage(img)
            self.avatar_label.setPixmap(pixmap.scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            self.avatar_label.setVisible(True)
            self.advice_context_area.append(f"<hr><h3>📸 Advanced Reverse Image Search</h3><p>Your Gravatar was found. Find where else your face appears:</p><ul><li><a href='{google_url}'>Search Google Lens</a></li><li><a href='{yandex_url}'>Search Yandex (Best for Faces)</a></li><li><a href='{tineye_url}'>Search TinEye (Exact Matches)</a></li></ul>")
        else:
            self.avatar_label.setText("Invalid Image")
            self.avatar_label.setVisible(True)

    def add_task_to_tree(self, category, task_html):
        parent = self.task_tree.findItems(category, Qt.MatchExactly, 0)
        if not parent:
            parent = QTreeWidgetItem([category])
            parent.setFont(0, QFont("Arial", 11, QFont.Bold))
            parent.setForeground(0, QColor("#0a84ff"))
            parent.setExpanded(True)
            self.task_tree.addTopLevelItem(parent)
        else:
            parent = parent[0]

        text = re.sub('<[^<]+?>', '', task_html).replace("Fix:", "\nFix:").replace("Nuclear Option:", "\nNuclear Option:").replace("View Archive", "\nView Archive")
        child = QTreeWidgetItem([text])
        child.setFlags(child.flags() | Qt.ItemIsUserCheckable)
        child.setCheckState(0, Qt.Unchecked)
        parent.addChild(child)

    def scan_complete(self, analytics, time_taken, total_checks):
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.reset_button.setEnabled(True)
        self.export_html_button.setEnabled(True)
        self.export_md_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Scan complete. Checked {total_checks} sources in {time_taken:.2f} seconds.")
        
        score = max(0, analytics["score"])
        self.score_label.setText(f"Privacy Risk Score: {score}/100")
        if score >= 80: self.score_label.setStyleSheet("color: #4caf50; font-weight: bold;")
        elif score >= 50: self.score_label.setStyleSheet("color: #ffa500; font-weight: bold;")
        else: self.score_label.setStyleSheet("color: #ff4c4c; font-weight: bold;")
        
        self.score_frame.setVisible(True)
        if not self.avatar_label.isVisible():
            self.avatar_label.setVisible(True)
            
        self.tabs.setCurrentIndex(1)
        self.statusBar().showMessage("Scan finished. Review your Action Plan.", 5000)

        save_scan_to_db(self.target_input.currentText(), score, analytics["exposures"])
        self.load_history()

    def load_history(self):
        history = fetch_history()
        self.history_table.setRowCount(0)
        for row_data in history:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            for col, data in enumerate(row_data):
                item = QTableWidgetItem(str(data))
                if col == 2:
                    try:
                        score = int(data)
                        if score >= 80: item.setForeground(Qt.green)
                        elif score >= 50: item.setForeground(Qt.yellow)
                        else: item.setForeground(Qt.red)
                    except ValueError:
                        pass
                self.history_table.setItem(row, col, item)

    def clear_history(self):
        reply = QMessageBox.question(self, 'Clear History', 'Are you sure you want to delete all scan history?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            clear_history_db()
            self.load_history()
            self.statusBar().showMessage("History cleared.", 3000)

    def export_csv(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Export History to CSV", "privacy_history.csv", "CSV Files (*.csv)")
        if file_name:
            history = fetch_history()
            with open(file_name, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Target", "Score", "Exposures"])
                writer.writerows(history)
            self.statusBar().showMessage(f"History exported to {file_name}", 5000)

    def reset_ui(self):
        self.target_input.setCurrentText("")
        self.results_area.clear()
        self.advice_context_area.clear()
        self.task_tree.clear()
        self.score_frame.setVisible(False)
        self.avatar_label.setVisible(False)
        self.status_label.setText("")
        self.tabs.setCurrentIndex(0)
        self.target_input.setFocus()

    def export_report(self, format_type):
        target = self.target_input.currentText()
        if format_type == "html":
            file_name, _ = QFileDialog.getSaveFileName(self, "Save Privacy Report", f"privacy_report_{target}.html", "HTML Files (*.html)")
            if file_name:
                tasks_html = "<ul>"
                for i in range(self.task_tree.topLevelItemCount()):
                    parent = self.task_tree.topLevelItem(i)
                    tasks_html += f"<li><b>{parent.text(0)}</b><ul>"
                    for j in range(parent.childCount()):
                        child = parent.child(j)
                        status = "[x]" if child.checkState(0) == Qt.Checked else "[ ]"
                        tasks_html += f"<li>{status} {child.text(0).replace(chr(10), '<br>')}</li>"
                    tasks_html += "</ul></li>"
                tasks_html += "</ul>"
                html_content = f"<html><head><style> body {{ font-family: sans-serif; line-height: 1.5; margin: 20px; }}</style></head><body><h1>Privacy Report for {target}</h1>{self.score_label.text()}<br><br>{self.advice_context_area.toHtml()}<h2>Action Plan</h2>{tasks_html}</body></html>"
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(html_content)
        else:
            file_name, _ = QFileDialog.getSaveFileName(self, "Save Privacy Report", f"privacy_report_{target}.md", "Markdown Files (*.md)")
            if file_name:
                md_content = f"# Privacy Report for {target}\n\n**{self.score_label.text()}**\n\n"
                md_content += "## Context & Intelligence\n"
                context_text = self.advice_context_area.toPlainText()
                md_content += context_text.replace("\n", "\n\n") + "\n\n"
                md_content += "## Action Plan Checklist\n"
                for i in range(self.task_tree.topLevelItemCount()):
                    parent = self.task_tree.topLevelItem(i)
                    md_content += f"### {parent.text(0)}\n"
                    for j in range(parent.childCount()):
                        child = parent.child(j)
                        status = "[x]" if child.checkState(0) == Qt.Checked else "[ ]"
                        md_content += f"- {status} {child.text(0).replace(chr(10), ' - ')}\n"
                    md_content += "\n"
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(md_content)
        self.statusBar().showMessage(f"Report saved to {file_name}", 5000)

if __name__ == "__main__":
    init_db()
    app = QApplication(sys.argv)
    app.setStyleSheet("""
        QMainWindow { background-color: #1e1e1e; }
        QWidget { color: #e0e0e0; }
        QLabel { color: #e0e0e0; }
        QFrame { background-color: #2d2d2d; border: 1px solid #444; border-radius: 5px; padding: 10px; }
        QTextEdit { background-color: #2d2d2d; color: #e0e0e0; border: 1px solid #444; font-family: Consolas, monospace; }
        QTreeWidget { background-color: #2d2d2d; color: #e0e0e0; border: 1px solid #444; }
        QTreeWidget::item:selected { background-color: #0a84ff; }
        QTableWidget { background-color: #2d2d2d; alternate-background-color: #333333; color: #e0e0e0; border: 1px solid #444; gridline-color: #444; }
        QTableWidget::item { padding: 5px; }
        QHeaderView::section { background-color: #1e1e1e; color: #e0e0e0; border: 1px solid #444; padding: 5px; }
        QTabWidget::pane { border: 1px solid #444; }
        QTabBar::tab { background-color: #2d2d2d; padding: 8px 20px; border: 1px solid #444; border-bottom: none; border-top-left-radius: 4px; border-top-right-radius: 4px; }
        QTabBar::tab:selected { background-color: #0a84ff; color: white; }
        QPushButton { background-color: #0a84ff; color: white; border: none; padding: 8px 16px; border-radius: 4px; font-weight: bold; }
        QPushButton:hover { background-color: #0066cc; }
        QPushButton:disabled { background-color: #555; color: #aaa; }
        QComboBox { padding: 8px; border: 1px solid #555; border-radius: 4px; background-color: #2d2d2d; color: #e0e0e0; }
        QComboBox QAbstractItemView { background-color: #2d2d2d; color: #e0e0e0; selection-background-color: #0a84ff; }
        QCheckBox { spacing: 5px; color: #e0e0e0; }
        QProgressBar { border: 1px solid #444; border-radius: 4px; text-align: center; background-color: #2d2d2d; color: white; }
        QProgressBar::chunk { background-color: #0a84ff; width: 10px; }
        QStatusBar { background-color: #2d2d2d; color: #aaa; }
    """)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())