# SQLI Scanner

*A fast, concurrent wrapper around **`sqlmap`** for triaging large URL lists from Termux or Linux. Futuristic terminal UI, sane defaults, and pragmatic controls so you can go wide first, then deep where it matters.*

> **Important**: This tool orchestrates `sqlmap` and does **not** exploit or patch systems. Use it only on assets you own or are authorized to test.

---

## ✨ Highlights

- **Mass triage** of hundreds/thousands of URLs with controlled concurrency
- **Two timeouts**: network timeout (`--timeout`) and *hard* process timeout (`--hard-timeout`) so scans don’t hang forever
- **Live status panel** with progress, successes, and last error snippets (powered by `rich`)
- ``** knobs** exposed: `--level`, `--risk`, and `--sqlmap-threads`
- **One-file input, one-file output**: simple `urls.txt` ➜ `vuln.txt`
- **Optional** `--no-tamper` to quickly disable default tamper scripts

---

## 🧩 Requirements

- **Python** ≥ 3.9 (3.10+ recommended)
- **sqlmap** in your `$PATH`
- **pip package:** [`rich`](https://pypi.org/project/rich/)

---

## 📦 Install

### Termux (Android)

```bash
pkg update -y
pkg install -y python git sqlmap
pip install --upgrade pip
pip install rich
# (optional) isolate with venv
python -m venv .venv && source .venv/bin/activate && pip install rich
```

### Debian/Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-pip git sqlmap
python3 -m pip install --upgrade pip
python3 -m pip install rich
# (optional) venv
python3 -m venv .venv && source .venv/bin/activate && pip install rich
```

### Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-pip sqlmap
python3 -m pip install --upgrade pip
python3 -m pip install rich
```

> **Alternative install for sqlmap** (if your repo is old):
>
> ```bash
> python3 -m pip install --user sqlmap
> # or via pipx
> python3 -m pip install --user pipx && pipx ensurepath && pipx install sqlmap
> ```

---

## 📥 Get the tool

Clone your repository and use the included script:

```bash
git clone https://github.com/<you>/<repo>.git
cd <repo>
# The script file lives here
ls sqli.py sqli_fixed.py 2>/dev/null || true
```

> There are two variants:
>
> - `sqli.py` — original
> - `sqli_fixed.py` — tuned version with `--hard-timeout`, better UI refresh, clearer error logs, and `--no-tamper` flag
>
> **Use **``** for best results.**

---

## 🧪 Quick Start

1. Prepare `urls.txt` — one URL per line (full URL including schema, e.g. `https://target.tld/page?id=1`).
2. Run a **quick triage** pass to identify promising targets:

```bash
python3 sqli_fixed.py -i urls.txt -o vuln.txt -c 8 \
  --timeout 15 --hard-timeout 300 \
  --sqlmap-threads 1 --level 2 --risk 1 --no-tamper
```

3. Re-run *only* on interesting hosts with **deeper** settings (higher level/risk, longer timeouts).

---

## ⚙️ Command-Line Reference

```text
usage: sqli_fixed.py -i <file> -o <file> [options]
```

| Option              | Type          | Default    | Description                                                                                                                                         |
| ------------------- | ------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-i, --input`       | path          | —          | Input file containing URLs (one per line).                                                                                                          |
| `-o, --output`      | path          | `vuln.txt` | File to append/save URLs flagged by `sqlmap` as vulnerable.                                                                                         |
| `-c, --concurrency` | int           | `16`       | Number of concurrent targets handled by the wrapper. Start smaller on Termux (e.g. 4–8).                                                            |
| `--timeout`         | int (seconds) | `25`       | **Network timeout** per HTTP request for `sqlmap`. Low values speed up triage but can miss slow apps.                                               |
| `--hard-timeout`    | int (seconds) | `180`      | **Hard cap** on each `sqlmap` process. When exceeded, the process is killed gracefully and marked as error. Increase for deep scans (e.g. 300–900). |
| `--sqlmap-threads`  | int           | `1`        | Internal parallel threads inside `sqlmap`. Keep small to avoid bans; raise carefully.                                                               |
| `--level`           | int `[1..5]`  | `5`        | `sqlmap` test level. Higher = more tests (slower). Start at `1–2` for triage.                                                                       |
| `--risk`            | int `[1..3]`  | `3`        | Risk profile for `sqlmap`. Higher may be noisier and slower.                                                                                        |
| `--no-tamper`       | flag          | off        | Disable the default tamper scripts (`between,randomcase,space2comment,charencode`). Useful when targets break on tampering.                         |

> **Note**: Other `sqlmap` flags (like proxies, user-agents, etc.) are not passed through by this wrapper. Adjust your environment or modify the script if you need them.

---

## 🖥️ Examples

### 1) Fast triage (Termux phone data, conservative)

```bash
python3 sqli_fixed.py -i urls.txt -o vuln.txt -c 4 \
  --timeout 12 --hard-timeout 240 --level 1 --risk 1 --no-tamper
```

### 2) Balanced desktop/laptop scan

```bash
python3 sqli_fixed.py -i urls.txt -o vuln.txt -c 8 \
  --timeout 20 --hard-timeout 420 --level 2 --risk 2 --sqlmap-threads 1
```

### 3) Deep dive for a few hosts

```bash
python3 sqli_fixed.py -i top10.txt -o vuln.txt -c 2 \
  --timeout 45 --hard-timeout 900 --level 5 --risk 3
```

---

## 📄 Input & Output

- **Input:** `urls.txt` — plain text, one URL per line. Examples:
  ```
  https://app.tld/products.php?id=1
  https://api.tld/v1/item?pid=77&lang=en
  http://legacy.tld/list.asp?cat=5
  ```
- **Output:** `vuln.txt` — lines of URLs that `sqlmap` reported as vulnerable (wrapper appends; remove the file to start fresh).

---

## 🚦 Exit Codes & Error Panel

The live UI shows counters:

- **Total** — how many lines parsed from input
- **Finished** — how many completed (success or fail)
- **Vulnerable** — URLs that `sqlmap` flagged as vulnerable
- **Errors** — wrapper-level failures (timeouts, `sqlmap` not found, network errors)

For each error, the panel prints the **last 3 lines** of `stderr/stdout` from `sqlmap` — this usually reveals if it was a **timeout**, **connection refused**, **403/Cloudflare**, or configuration issue.

---

## 🧠 Tuning Tips

- Start **wide and shallow**: low `--level`/`--risk`, short `--timeout`, moderate `--hard-timeout`.
- On unstable networks (mobile/Termux), keep `--concurrency` low (4–8) and consider `--no-tamper`.
- If you see many `Timeout > ...s` errors, raise `--hard-timeout` or lower `--concurrency`.
- Targets with WAF/CDN may rate-limit aggressively; slow down and revisit with longer timeouts.

---

## 🔧 Troubleshooting

- `` → Install it and ensure it’s on `$PATH` (see Install section). Try `which sqlmap`.
- **Many timeouts** → Increase `--hard-timeout` (e.g., 300–900), reduce `--concurrency`, or lower `--level`/`--risk`.
- **Network/DNS errors** → Test connectivity: `curl -I <url>`. On Termux, check data permissions and VPN/Proxy settings.
- **Permission issues on Termux** → Make sure storage permission is granted (`termux-setup-storage`) if your files are in shared storage.

---

## 🛡️ Legal & Ethics

Only test systems you are authorized to assess. Unauthorized scanning may be illegal and unethical. You are responsible for complying with laws and contracts in your jurisdiction.

---

## 📜 License

Choose a license that fits your project (e.g., MIT/Apache-2.0/GPL-3.0) and place it as `LICENSE` at repo root.

---

## 🤝 Credits

- [`sqlmap`](https://github.com/sqlmapproject/sqlmap) — the engine doing the heavy lifting
- [`rich`](https://github.com/Textualize/rich) — terminal UI components

---

## 🗺️ Roadmap (future-looking)

- Pass-through for advanced `sqlmap` flags (proxy, UA, cookie jar)
- Session caching and resume
- Target deduplication & per-host rate limiting
- JSON/CSV structured output
- Container image for reproducible runs

> PRs welcome! Open issues with logs (mask sensitive parts) so we can tune defaults together.

