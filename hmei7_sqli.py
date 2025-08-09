#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Hmei7 - SQLi Scanner (Realtime, Futuristic UI)
- Paralel (asyncio) untuk scan ratusan URL
- Dashboard realtime dengan Rich
- Header ASCII ungu neon dalam panel futuristik
- Kompatibel argumen: -i, -o, -c, --timeout, --sqlmap-threads, --level, --risk
- Tidak memakai opsi sqlmap yang invalid (contoh: --stop-on-first)

⚠️ Gunakan di lingkungan yang Anda miliki izin eksplisit untuk diuji.
"""

import argparse
import asyncio
import os
import re
import signal
import sys
from pathlib import Path
from typing import List, Tuple, Optional, Set

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress,
    BarColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
    TextColumn,
    SpinnerColumn,
)
from rich.table import Table
from rich.text import Text
from rich.layout import Layout
from rich.syntax import Syntax

from pyfiglet import Figlet

console = Console()

# ---------- UI BUILDERS ----------

def make_header() -> Panel:
    f = Figlet(font="slant")  # coba juga 'ansi_shadow' / 'standard' kalau ingin beda
    ascii_text = f.renderText("Hmei7 - SQLi Scanner")
    ascii_rich = Text(ascii_text, style="bold magenta")
    sub = Text("parallel • neon grid • live telemetry", style="bright_white on magenta")
    inner = Group(Align.center(ascii_rich), Align.center(sub))
    return Panel(
        inner,
        title=Text(" ", style="bold magenta"),
        border_style="magenta",
        box=box.HEAVY,
        padding=(1, 2),
    )


def make_stats_panel(total:int, done:int, vuln:int, errors:int) -> Panel:
    grid = Table.grid(padding=(0,1))
    grid.add_column(justify="right")
    grid.add_column(justify="left")

    grid.add_row("Total", f"[white]{total}[/]")
    grid.add_row("Selesai", f"[cyan]{done}[/]")
    grid.add_row("Vulnerable", f"[bold green]{vuln}[/]")
    grid.add_row("Errors", f"[bold red]{errors}[/]")

    return Panel(grid, title="[bold]Stats", border_style="magenta", box=box.ROUNDED)


def make_vuln_table(vuln_items: List[Tuple[str,str]]) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, border_style="magenta")
    table.add_column("No", justify="right", width=3)
    table.add_column("URL", overflow="fold")
    table.add_column("Evidence", overflow="fold", style="green")

    for i,(url,evidence) in enumerate(vuln_items, start=1):
        table.add_row(str(i), url, evidence)

    return Panel(table, title="[bold green]VULNERABLE FOUND", border_style="green", box=box.ROUNDED)


def make_log_panel(lines: List[str], max_lines:int=14) -> Panel:
    if len(lines) > max_lines:
        view = lines[-max_lines:]
    else:
        view = lines
    rendered = "\n".join(view) if view else "—"
    return Panel(
        Syntax(rendered, "bash", word_wrap=True, theme="ansi_dark"),
        title="[bold]Activity Log",
        border_style="magenta",
        box=box.ROUNDED,
        padding=(0,1),
    )


def build_layout(progress: Progress,
                 total:int, done:int, vuln:int, errors:int,
                 vuln_items: List[Tuple[str,str]],
                 logs: List[str]) -> Layout:
    layout = Layout()
    layout.split(
        Layout(name="header", size=10),
        Layout(name="body", ratio=1),
    )
    layout["header"].update(make_header())

    layout["body"].split_row(
        Layout(name="left", ratio=2),
        Layout(name="right", ratio=1),
    )

    left = Layout()
    left.split(
        Layout(Panel(progress, title="[bold]Progress", border_style="magenta", box=box.ROUNDED), size=7),
        Layout(make_vuln_table(vuln_items))
    )

    layout["left"].update(left)
    layout["right"].split(
        Layout(make_stats_panel(total, done, vuln, errors), size=10),
        Layout(make_log_panel(logs))
    )

    return layout

# ---------- CORE SCANNER ----------

# regex sederhana milik sqlmap untuk indikasi vuln (bisa ditambah variannya)
VULN_MARKERS = [
    r"sql injection vulnerability",
    r"is vulnerable to (?:boolean|time|error)-based",
    r"parameter '.*?' is vulnerable",
]

def looks_vulnerable(sqlmap_output: str) -> Optional[str]:
    for pat in VULN_MARKERS:
        m = re.search(pat, sqlmap_output, re.IGNORECASE)
        if m:
            return m.group(0)
    return None

def build_sqlmap_cmd(url: str, args) -> List[str]:
    # ganti "FUZZ" -> "1" agar tidak bikin sqlmap bingung
    url_fixed = url.replace("FUZZ", "1")

    cmd = [
        "sqlmap",
        "-u", url_fixed,
        "--batch",
        "--level", str(args.level),
        "--risk", str(args.risk),
        "--technique", "BEU",
        "--random-agent",
        "--timeout", str(args.timeout),
        "--threads", str(args.sqlmap_threads),
        "--fresh-queries",
        "--tamper", "between,randomcase,space2comment,charencode"
    ]
    # jangan pakai opsi yang invalid seperti --stop-on-first
    return cmd

async def run_cmd(cmd: List[str], timeout: int) -> Tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "", f"Timeout > {timeout+5}s"
    return proc.returncode, out.decode(errors="ignore"), err.decode(errors="ignore")

async def worker(name: str,
                 queue: asyncio.Queue,
                 progress_task_id,
                 progress: Progress,
                 args,
                 live_state):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break

        url = item
        progress.advance(progress_task_id, 1)
        live_state["done"] += 1
        live_state["logs"].append(f"[SCAN] {url}")

        cmd = build_sqlmap_cmd(url, args)
        code, out, err = await run_cmd(cmd, timeout=args.timeout)

        if code == 0:
            ev = looks_vulnerable(out)
            if ev:
                if url not in live_state["vuln_seen"]:
                    live_state["vuln_seen"].add(url)
                    live_state["vuln_items"].append((url, ev))
                    live_state["logs"].append(f"[VULN] {url}  ← {ev}")
                    # append ke file
                    try:
                        with open(args.output, "a", encoding="utf-8") as fo:
                            fo.write(url + "\n")
                    except Exception as e:
                        live_state["logs"].append(f"[ERROR] write {args.output}: {e}")
            else:
                live_state["logs"].append(f"[SAFE] {url}")
        else:
            live_state["errors"] += 1
            # ambil sebagian error agar log tetap ringkas
            snippet = (err or out or "error").strip().splitlines()[-1:]  # last line
            msg = snippet[0] if snippet else "error"
            live_state["logs"].append(f"[ERROR] {url} → {msg}")

        queue.task_done()


async def main_async(args):
    # load urls
    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        urls = [u.strip() for u in f if u.strip()]

    # filter: hanya URL yang punya parameter
    urls = [u for u in urls if "?" in u and "=" in u]

    total = len(urls)
    if total == 0:
        console.print("[bold red]Tidak ada URL dengan parameter untuk dipindai.[/]")
        return

    # siapkan output file (clean)
    Path(args.output).write_text("", encoding="utf-8")

    # state untuk UI
    live_state = {
        "total": total,
        "done": 0,
        "errors": 0,
        "vuln_items": [],               # List[Tuple[url, evidence]]
        "vuln_seen": set(),             # Set[str]
        "logs": []
    }

    # progress bar
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("{task.percentage:>5.1f}%"),
        TimeElapsedColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
        expand=True,
        transient=False,
    )
    task_id = progress.add_task("[bold]Scanning", total=total)

    # queue & workers
    queue: asyncio.Queue = asyncio.Queue()
    for u in urls:
        await queue.put(u)
    # sentinel
    for _ in range(args.concurrency):
        await queue.put(None)

    layout = build_layout(
        progress,
        live_state["total"], live_state["done"],
        len(live_state["vuln_items"]), live_state["errors"],
        live_state["vuln_items"], live_state["logs"]
    )

    async def refresher(live: Live):
        # refresh UI loop
        while not progress.finished or not queue.empty():
            layout = build_layout(
                progress,
                live_state["total"], live_state["done"],
                len(live_state["vuln_items"]), live_state["errors"],
                live_state["vuln_items"], live_state["logs"]
            )
            live.update(layout)
            await asyncio.sleep(0.08)

    # handle Ctrl+C agar UI rapi
    stop_event = asyncio.Event()
    def sigint_handler(*_):
        live_state["logs"].append("[!] Interrupt received, waiting workers to finish…")
        stop_event.set()
    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, sigint_handler)
    except Exception:
        # Windows old versions may not support
        pass

    with Live(layout, console=console, refresh_per_second=30, screen=True):
        # start tasks
        workers = [
            asyncio.create_task(worker(f"W{i+1}", queue, task_id, progress, args, live_state))
            for i in range(args.concurrency)
        ]

        # run progress task in background (advance is in worker)
        async def drive_progress():
            # no-op, workers advance the bar
            while live_state["done"] < total and not stop_event.is_set():
                await asyncio.sleep(0.2)

        runner = asyncio.create_task(drive_progress())
        painter = asyncio.create_task(refresher(console))

        await asyncio.gather(*workers)
        progress.update(task_id, completed=total)
        await queue.join()

        # stop painter
        painter.cancel()
        with contextlib.suppress(Exception):
            await painter

    # final summary
    console.print()
    console.rule("[bold magenta]Summary")
    console.print(f"[white]Total:[/] {total}  •  [cyan]Selesai:[/] {live_state['done']}  •  "
                  f"[bold green]Vulnerable:[/] {len(live_state['vuln_items'])}  •  "
                  f"[bold red]Errors:[/] {live_state['errors']}")
    console.print(f"[green]Saved:[/] {args.output}")

# ---------- CLI ----------

import contextlib

def parse_args():
    p = argparse.ArgumentParser(
        description="Hmei7 - SQLi Scanner (Realtime)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    p.add_argument("-i","--input", required=True, help="file daftar URL (satu per baris)")
    p.add_argument("-o","--output", required=True, help="file output URL vuln")
    p.add_argument("-c","--concurrency", type=int, default=16, help="jumlah worker paralel")
    p.add_argument("--timeout", type=int, default=25, help="timeout per target (detik)")
    p.add_argument("--sqlmap-threads", type=int, default=1, help="threads internal sqlmap")
    p.add_argument("--level", type=int, default=5, help="level sqlmap")
    p.add_argument("--risk", type=int, default=3, help="risk sqlmap")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    # Validasi ringan
    if not Path(args.input).exists():
        console.print(f"[bold red]Input file tidak ditemukan:[/] {args.input}")
        sys.exit(1)

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        console.print("\n[bold red]Dihentikan oleh pengguna.[/]")
