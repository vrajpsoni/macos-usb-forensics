#!/usr/bin/env python3
"""
usb_trace.py — macOS USB Device Forensics Analysis Script
CS 480 Digital Forensics — Final Project

Collects forensic artifacts from macOS to reconstruct USB device activity
and potential data exfiltration events.

Usage:
    python usb_trace.py                            # full run
    python usb_trace.py collect                    # collect only, save to cache
    python usb_trace.py timeline                   # print timeline from cache
    python usb_trace.py report                     # full report from cache
    python usb_trace.py --target ~/Desktop/Folder  # specify evidence folder
    python usb_trace.py --hours 48                 # look back 48 hours
    python usb_trace.py --output report.txt        # write report to file
"""

import argparse
import csv
import json
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPORT_WIDTH = 80
SEP = "=" * REPORT_WIDTH
THIN = "-" * REPORT_WIDTH
CACHE_FILE = Path("/tmp/usb_forensics_cache.json")
DEFAULT_HOURS = 24
DEFAULT_TARGET = str(Path.home() / "Desktop" / "UMass_Confidential")

SUSPICIOUS_CMD_PATTERNS = [
    r"\bcp\b",
    r"\brsync\b",
    r"\bditto\b",
    r"\bscp\b",
    r"\btar\b.*-c",
    r"/Volumes/",
    r"\bdd\b",
]


# ---------------------------------------------------------------------------
# Core subprocess helper
# ---------------------------------------------------------------------------

def run_cmd(cmd: list, timeout: int = 90) -> tuple:
    """Run a subprocess. Returns (stdout, stderr, returncode). Never raises."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -1
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s: {' '.join(cmd[:3])}", -2
    except Exception as e:
        return "", str(e), -3


def _progress(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Timestamp utilities
# ---------------------------------------------------------------------------

_TS_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S %z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
]


def parse_timestamp(ts_str: str):
    """Return datetime or None. Handles common macOS log and mdls formats."""
    if not ts_str or ts_str.strip() in ("", "(null)", "null"):
        return None
    ts_str = ts_str.strip()
    # log show sometimes emits "+0000" as timezone — normalize
    ts_str = re.sub(r"\s+\+0000$", "+0000", ts_str)
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def fmt_ts(dt) -> str:
    if dt is None:
        return "TIMESTAMP_UNKNOWN"
    return dt.strftime("%Y-%m-%dT%H:%M:%S%z")


# ---------------------------------------------------------------------------
# Log output parser (handles JSON array or NDJSON from log show)
# ---------------------------------------------------------------------------

def parse_log_output(raw: str) -> list:
    raw = raw.strip()
    if not raw:
        return []
    if raw.startswith("["):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
    # fallback: NDJSON
    results = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return results


def _normalize_log_event(raw: dict, source: str) -> dict:
    return {
        "timestamp": raw.get("timestamp", raw.get("traceID", "")),
        "subsystem": raw.get("subsystem", ""),
        "category": raw.get("category", ""),
        "process": raw.get("processImagePath", raw.get("senderImagePath", "")),
        "message": raw.get("eventMessage", ""),
        "source": source,
    }


# ---------------------------------------------------------------------------
# Section A: USB log events
# ---------------------------------------------------------------------------

def collect_usb_log_events(hours_back: int) -> list:
    _progress(f"Querying USB events from unified log (last {hours_back}h) — may take 30s...")
    predicate = (
        'subsystem == "com.apple.DiskArbitration" '
        'OR subsystem == "com.apple.iokit.IOUSBDevice" '
        'OR subsystem == "com.apple.driver.usb.massstorage" '
        'OR (eventMessage CONTAINS "USB") '
        'OR (eventMessage CONTAINS "disk" AND eventMessage CONTAINS "mount") '
        'OR processImagePath CONTAINS "diskmanagementd" '
        'OR processImagePath CONTAINS "diskarbitrationd"'
    )
    cmd = ["log", "show", "--last", f"{hours_back}h", "--style", "json",
           "--predicate", predicate]
    stdout, stderr, rc = run_cmd(cmd, timeout=120)
    if rc != 0 and not stdout.strip():
        if "permission" in stderr.lower() or "access" in stderr.lower() or not stdout:
            print("  [!] log show returned no data. Check: System Settings > Privacy & Security")
            print("      > Full Disk Access — ensure Terminal.app is listed and enabled.")
        return []
    raw_events = parse_log_output(stdout)
    return [_normalize_log_event(e, "usb_log") for e in raw_events]


# ---------------------------------------------------------------------------
# Section B: Disk mount/unmount events
# ---------------------------------------------------------------------------

def collect_disk_events(hours_back: int) -> list:
    _progress(f"Querying disk mount/unmount events (last {hours_back}h)...")
    predicate = (
        '(eventMessage CONTAINS "mounted") '
        'OR (eventMessage CONTAINS "unmounted") '
        'OR (eventMessage CONTAINS "Mounted") '
        'OR (eventMessage CONTAINS "Unmounted") '
        'OR subsystem == "com.apple.diskmanagement"'
    )
    cmd = ["log", "show", "--last", f"{hours_back}h", "--style", "json",
           "--predicate", predicate]
    stdout, _, rc = run_cmd(cmd, timeout=120)
    if not stdout.strip():
        return []
    raw_events = parse_log_output(stdout)
    return [_normalize_log_event(e, "disk_log") for e in raw_events]


# ---------------------------------------------------------------------------
# Section C: USB device inventory
# ---------------------------------------------------------------------------

def _walk_usb_items(items: list) -> list:
    devices = []
    for item in items:
        if "_items" in item:
            devices.extend(_walk_usb_items(item["_items"]))
        if "vendor_id" in item:
            devices.append({
                "name": item.get("_name", "Unknown"),
                "vendor_id": item.get("vendor_id", ""),
                "product_id": item.get("product_id", ""),
                "serial": item.get("serial_num", ""),
                "manufacturer": item.get("manufacturer", ""),
                "speed": item.get("speed", ""),
                "source": "system_profiler",
            })
    return devices


def collect_usb_devices() -> list:
    _progress("Querying USB device inventory (system_profiler)...")
    stdout, _, rc = run_cmd(["system_profiler", "SPUSBDataType", "-json"], timeout=30)
    if rc != 0 or not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    top_items = data.get("SPUSBDataType", [])
    return _walk_usb_items(top_items)


# ---------------------------------------------------------------------------
# Section D: File metadata
# ---------------------------------------------------------------------------

def _run_mdls(path: Path) -> dict:
    keys = [
        "kMDItemFSCreationDate", "kMDItemLastUsedDate",
        "kMDItemDateAdded", "kMDItemContentModificationDate",
        "kMDItemContentType", "kMDItemDisplayName", "kMDItemFSSize",
    ]
    cmd = ["mdls"] + [arg for k in keys for arg in ("-name", k)] + [str(path)]
    stdout, _, _ = run_cmd(cmd, timeout=15)
    result = {}
    for line in stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            v = v.strip().strip('"')
            result[k.strip()] = None if v in ("(null)", "") else v
    return result


def _run_stat(path: Path) -> dict:
    fmt = "atime=%Sa|mtime=%Sm|ctime=%Sc|birthtime=%SB|size=%z|inode=%i|mode=%Sp"
    stdout, _, rc = run_cmd(
        ["stat", "-f", fmt, "-t", "%Y-%m-%dT%H:%M:%S%z", str(path)], timeout=10
    )
    result = {}
    if rc == 0 and stdout.strip():
        for part in stdout.strip().split("|"):
            if "=" in part:
                k, _, v = part.partition("=")
                result[k.strip()] = v.strip() or None
    return result


def collect_file_metadata(folder: Path) -> list:
    _progress(f"Reading file metadata for {folder} ...")
    if not folder.exists():
        print(f"  [!] Target folder not found: {folder}")
        return []
    records = []
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.name == ".DS_Store":
            continue
        mdls = _run_mdls(path)
        stat = _run_stat(path)
        records.append({
            "path": str(path),
            "name": path.name,
            "size_bytes": stat.get("size"),
            "inode": stat.get("inode"),
            "mode": stat.get("mode"),
            "birthtime": stat.get("birthtime"),
            "mtime": stat.get("mtime"),
            "atime": stat.get("atime"),
            "ctime": stat.get("ctime"),
            "mdls_creation": mdls.get("kMDItemFSCreationDate"),
            "mdls_last_used": mdls.get("kMDItemLastUsedDate"),
            "mdls_date_added": mdls.get("kMDItemDateAdded"),
            "mdls_modified": mdls.get("kMDItemContentModificationDate"),
            "mdls_content_type": mdls.get("kMDItemContentType"),
            "source": "file_metadata",
        })
    return records


# ---------------------------------------------------------------------------
# Section E: Finder recent destinations
# ---------------------------------------------------------------------------

def collect_finder_destinations() -> list:
    _progress("Checking Finder recent copy/move destinations...")
    stdout, _, rc = run_cmd(
        ["defaults", "read", "com.apple.finder", "RecentMoveAndCopyDestinations"],
        timeout=10,
    )
    if rc != 0 or not stdout.strip():
        return []
    paths = re.findall(r'"(file://[^"]+)"', stdout)
    if not paths:
        paths = re.findall(r'"([^"]+)"', stdout)
    return paths


# ---------------------------------------------------------------------------
# Section F: Shell history
# ---------------------------------------------------------------------------

def _is_suspicious(cmd_line: str) -> bool:
    for pattern in SUSPICIOUS_CMD_PATTERNS:
        if re.search(pattern, cmd_line):
            return True
    return False


def _parse_zsh_history(path: Path) -> list:
    matches = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Extended zsh format: ": timestamp:elapsed;command"
        m = re.match(r"^:\s*(\d+):\d+;(.+)$", line)
        if m:
            ts_epoch = int(m.group(1))
            cmd_line = m.group(2)
            try:
                ts = datetime.fromtimestamp(ts_epoch, tz=timezone.utc)
                ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S%z")
            except (OSError, OverflowError):
                ts_str = None
        else:
            cmd_line = line
            ts_str = None
        if _is_suspicious(cmd_line):
            matches.append({
                "history_file": str(path),
                "line_number": i + 1,
                "command": cmd_line,
                "timestamp": ts_str,
                "source": "shell_history",
            })
        i += 1
    return matches


def _parse_bash_history(path: Path) -> list:
    matches = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    pending_ts = None
    for i, line in enumerate(lines):
        # bash HISTTIMEFORMAT timestamps appear as "#epoch" lines
        m = re.match(r"^#(\d{10})$", line)
        if m:
            try:
                ts = datetime.fromtimestamp(int(m.group(1)), tz=timezone.utc)
                pending_ts = ts.strftime("%Y-%m-%dT%H:%M:%S%z")
            except (OSError, OverflowError):
                pending_ts = None
            continue
        if _is_suspicious(line):
            matches.append({
                "history_file": str(path),
                "line_number": i + 1,
                "command": line,
                "timestamp": pending_ts,
                "source": "shell_history",
            })
        pending_ts = None
    return matches


def collect_shell_history() -> list:
    _progress("Scanning shell history for suspicious copy commands...")
    results = []
    candidates = [
        (Path.home() / ".zsh_history", _parse_zsh_history),
        (Path.home() / ".bash_history", _parse_bash_history),
        (Path.home() / ".sh_history", _parse_bash_history),
    ]
    for path, parser in candidates:
        if path.exists():
            found = parser(path)
            results.extend(found)
    return results


# ---------------------------------------------------------------------------
# Section G: .DS_Store + QuickLook
# ---------------------------------------------------------------------------

def check_ds_store(folder: Path) -> bool:
    return (folder / ".DS_Store").exists()


def check_quicklook_cache(folder: Path) -> list:
    _progress("Checking QuickLook cache...")
    found = []
    var_folders = Path("/var/folders")
    if var_folders.exists():
        for entry in var_folders.rglob("com.apple.QuickLook*"):
            found.append(str(entry))
            if len(found) >= 5:
                break
    return found


# ---------------------------------------------------------------------------
# Timeline builder
# ---------------------------------------------------------------------------

def _classify_log_event(event: dict) -> str:
    msg = event.get("message", "").lower()
    if "disconnect" in msg or "removed" in msg or "unplugged" in msg:
        return "USB_DEVICE_DISCONNECT"
    if "usb" in msg or "iokit" in event.get("subsystem", "").lower():
        return "USB_DEVICE_CONNECT"
    if "unmount" in msg:
        return "VOLUME_UNMOUNT"
    if "mount" in msg:
        return "VOLUME_MOUNT"
    return "USB_LOG_EVENT"


def build_timeline(evidence: dict) -> list:
    entries = []

    # USB log events
    for e in evidence.get("usb_log_events", []):
        dt = parse_timestamp(e.get("timestamp", ""))
        entries.append({
            "timestamp": dt,
            "timestamp_str": fmt_ts(dt),
            "event_type": _classify_log_event(e),
            "detail": e.get("message", "")[:120],
            "source": "usb_log",
            "confidence": "high",
        })

    # Disk events
    for e in evidence.get("disk_events", []):
        dt = parse_timestamp(e.get("timestamp", ""))
        msg = e.get("message", "")
        etype = "VOLUME_UNMOUNT" if "unmount" in msg.lower() else "VOLUME_MOUNT"
        entries.append({
            "timestamp": dt,
            "timestamp_str": fmt_ts(dt),
            "event_type": etype,
            "detail": msg[:120],
            "source": "disk_log",
            "confidence": "high",
        })

    # File metadata — atime, mtime, birthtime
    for f in evidence.get("file_metadata", []):
        for ts_key, etype in [
            ("birthtime", "FILE_CREATED"),
            ("mtime", "FILE_MODIFIED"),
            ("atime", "FILE_ACCESSED"),
        ]:
            ts_str = f.get(ts_key)
            if ts_str:
                dt = parse_timestamp(ts_str)
                entries.append({
                    "timestamp": dt,
                    "timestamp_str": fmt_ts(dt),
                    "event_type": etype,
                    "detail": f.get("name", ""),
                    "source": "file_metadata",
                    "confidence": "medium" if etype == "FILE_ACCESSED" else "high",
                })
        mdls_used = f.get("mdls_last_used")
        if mdls_used:
            dt = parse_timestamp(mdls_used)
            entries.append({
                "timestamp": dt,
                "timestamp_str": fmt_ts(dt),
                "event_type": "FILE_LAST_USED",
                "detail": f.get("name", "") + " (Spotlight kMDItemLastUsedDate)",
                "source": "file_metadata",
                "confidence": "high",
            })

    # Shell history
    for h in evidence.get("shell_history", []):
        dt = parse_timestamp(h.get("timestamp", "")) if h.get("timestamp") else None
        entries.append({
            "timestamp": dt,
            "timestamp_str": fmt_ts(dt),
            "event_type": "SHELL_COPY_CMD",
            "detail": h.get("command", "")[:120],
            "source": "shell_history",
            "confidence": "high",
        })

    # Finder destinations — no timestamp
    for dest in evidence.get("finder_destinations", []):
        entries.append({
            "timestamp": None,
            "timestamp_str": "TIMESTAMP_UNKNOWN",
            "event_type": "FINDER_DESTINATION_RECORDED",
            "detail": dest,
            "source": "finder_prefs",
            "confidence": "high",
        })

    # Sort: known timestamps first (chronologically), unknowns at end
    known = [e for e in entries if e["timestamp"] is not None]
    unknown = [e for e in entries if e["timestamp"] is None]
    known.sort(key=lambda e: e["timestamp"])
    return known + unknown


# ---------------------------------------------------------------------------
# Report formatter
# ---------------------------------------------------------------------------

def _emit(line: str = "", f=None) -> None:
    print(line)
    if f:
        f.write(line + "\n")


def _section(title: str, f=None) -> None:
    _emit(f"\n[{title}]", f)
    _emit(THIN, f)


def format_report(evidence: dict, outpath: Path = None) -> None:
    fh = open(outpath, "w", encoding="utf-8") if outpath else None
    try:
        _report_body(evidence, fh)
    finally:
        if fh:
            fh.close()


def _report_body(evidence: dict, f=None) -> None:
    collected_at = evidence.get("collected_at", "Unknown")
    target = evidence.get("target_folder", "Unknown")
    hours = evidence.get("hours_back", DEFAULT_HOURS)

    _emit(SEP, f)
    _emit("              macOS USB FORENSIC ANALYSIS REPORT", f)
    _emit(SEP, f)
    _emit(f"  Case Number   : [FILL IN]", f)
    _emit(f"  Examiner      : [FILL IN]", f)
    _emit(f"  Date/Time     : {collected_at}", f)
    _emit(f"  Target Folder : {target}", f)
    _emit(f"  Log Window    : Last {hours} hours", f)
    _emit(f"  macOS Version : {platform.mac_ver()[0] or 'Unknown'}", f)
    _emit(SEP, f)

    # Section 1: USB device inventory
    _section("1  USB DEVICE INVENTORY  (system_profiler SPUSBDataType)", f)
    _emit("  What was looked for: Currently connected USB storage devices", f)
    devices = evidence.get("usb_devices", [])
    if devices:
        _emit(f"  What was found: {len(devices)} USB device(s)\n", f)
        for dev in devices:
            _emit(f"    Device Name   : {dev.get('name', 'Unknown')}", f)
            _emit(f"    Manufacturer  : {dev.get('manufacturer', 'N/A')}", f)
            _emit(f"    Vendor ID     : {dev.get('vendor_id', 'N/A')}", f)
            _emit(f"    Product ID    : {dev.get('product_id', 'N/A')}", f)
            _emit(f"    Serial Number : {dev.get('serial', 'N/A')}", f)
            _emit(f"    Speed         : {dev.get('speed', 'N/A')}", f)
            _emit("", f)
        _emit("  Forensic Significance: Serial number provides a unique hardware", f)
        _emit("  identifier that can be matched against log entries and the physical", f)
        _emit("  device if recovered.", f)
    else:
        _emit("  What was found: No USB storage devices currently connected.", f)
        _emit("  (Device may have already been removed — check log events below.)", f)

    # Section 2: USB log events
    _section("2  USB CONNECTION EVENTS  (unified log — IOUSBDevice / DiskArbitration)", f)
    usb_events = evidence.get("usb_log_events", [])
    _emit(f"  What was looked for: USB connect/disconnect events in the macOS", f)
    _emit(f"  Unified Log over the past {hours} hours", f)
    _emit(f"  What was found: {len(usb_events)} event(s)\n", f)
    for e in usb_events[:30]:
        ts = e.get("timestamp", "")[:19]
        msg = e.get("message", "")[:60]
        _emit(f"    {ts}  {msg}", f)
    if len(usb_events) > 30:
        _emit(f"    ... ({len(usb_events) - 30} more events truncated)", f)
    if not usb_events:
        _emit("  No USB events found in the log window.", f)
        _emit("  If this is unexpected, verify Terminal has Full Disk Access.", f)
    _emit("\n  Forensic Significance: USB connection/disconnection times define the", f)
    _emit("  incident window. File activity within this window is highly relevant.", f)

    # Section 3: Disk events
    _section("3  VOLUME MOUNT / UNMOUNT EVENTS  (unified log)", f)
    disk_events = evidence.get("disk_events", [])
    _emit(f"  What was found: {len(disk_events)} event(s)\n", f)
    for e in disk_events[:20]:
        ts = e.get("timestamp", "")[:19]
        msg = e.get("message", "")[:65]
        _emit(f"    {ts}  {msg}", f)
    if not disk_events:
        _emit("  No mount/unmount events found in the log window.", f)
    _emit("\n  Forensic Significance: Mount events confirm when the USB volume became", f)
    _emit("  accessible; unmount events show when it was ejected.", f)

    # Section 4: File metadata
    _section("4  FILE METADATA ANALYSIS  (mdls + stat)", f)
    file_meta = evidence.get("file_metadata", [])
    _emit("  What was looked for: File timestamps (creation, modification, access)", f)
    _emit("  and Spotlight metadata for all files in the target folder\n", f)

    usb_start = usb_end = None
    usb_log = evidence.get("usb_log_events", [])
    if usb_log:
        ts_list = [parse_timestamp(e.get("timestamp", "")) for e in usb_log]
        ts_list = [t for t in ts_list if t]
        if ts_list:
            usb_start = min(ts_list)
            usb_end = max(ts_list)

    atime_hits = 0
    for fm in file_meta:
        _emit(f"  File: {fm['name']}", f)
        for label, key in [
            ("  Birth (created) ", "birthtime"),
            ("  Modified (mtime)", "mtime"),
            ("  Accessed (atime)", "atime"),
            ("  Metadata (ctime)", "ctime"),
            ("  Last Used (mdls) ", "mdls_last_used"),
        ]:
            val = fm.get(key)
            if val:
                note = ""
                if key == "atime" and usb_start:
                    dt = parse_timestamp(val)
                    if dt and usb_start <= dt <= usb_end:
                        note = "  <-- DURING USB WINDOW"
                        atime_hits += 1
                _emit(f"    {label}: {val}{note}", f)
        _emit(f"    Size            : {fm.get('size_bytes', 'N/A')} bytes", f)
        _emit("", f)

    if atime_hits > 0:
        _emit(f"  Forensic Significance: {atime_hits} file(s) had atime updated during", f)
        _emit("  the USB connection window — strongly consistent with a read/copy operation.", f)
    else:
        _emit("  Forensic Significance: File timestamps recorded; compare atime values", f)
        _emit("  against USB connection window from Section 2 to identify accessed files.", f)

    # Section 5: Finder destinations
    _section("5  FINDER RECENT DESTINATIONS  (com.apple.finder preferences)", f)
    destinations = evidence.get("finder_destinations", [])
    _emit("  What was looked for: Recent Finder copy/move destination paths\n", f)
    if destinations:
        _emit(f"  What was found: {len(destinations)} destination(s)\n", f)
        for d in destinations:
            _emit(f"    {d}", f)
        _emit("\n  Forensic Significance: If /Volumes/<USB_NAME>/ appears here, it is", f)
        _emit("  direct evidence that Finder performed a copy/move to the USB device.", f)
    else:
        _emit("  What was found: No recent Finder destinations recorded.", f)
        _emit("  (Key may not exist if Finder copy was not used.)", f)

    # Section 6: Shell history
    _section("6  SHELL HISTORY MATCHES", f)
    hist = evidence.get("shell_history", [])
    _emit("  What was looked for: cp, rsync, ditto, scp, dd, /Volumes/ references\n", f)
    if hist:
        _emit(f"  What was found: {len(hist)} matching command(s)\n", f)
        for h in hist:
            ts = h.get("timestamp") or "timestamp unknown"
            _emit(f"    {h['history_file']}:{h['line_number']}  [{ts}]", f)
            _emit(f"      {h['command']}", f)
            _emit("", f)
        _emit("  Forensic Significance: Explicit copy commands with destination paths", f)
        _emit("  provide direct evidence of intent and method.", f)
    else:
        _emit("  What was found: No suspicious commands in shell history.", f)
        _emit("  (History may have been cleared, or Finder drag-and-drop was used.)", f)

    # Section 7: .DS_Store
    _section("7  .DS_STORE EVIDENCE", f)
    ds = evidence.get("ds_store_present", False)
    _emit("  What was looked for: .DS_Store file in the target folder\n", f)
    if ds:
        _emit(f"  What was found: PRESENT — {target}/.DS_Store", f)
        _emit("\n  Forensic Significance: macOS Finder creates .DS_Store when it renders", f)
        _emit("  a directory. Its presence confirms Finder opened and displayed this", f)
        _emit("  folder — consistent with browsing before copying.", f)
    else:
        _emit("  What was found: ABSENT — .DS_Store not found in target folder.", f)

    # Section 8: QuickLook cache
    _section("8  QUICKLOOK CACHE", f)
    ql = evidence.get("quicklook_cache", [])
    _emit("  What was looked for: QuickLook thumbnail cache directories\n", f)
    if ql:
        _emit(f"  What was found: {len(ql)} cache location(s)\n", f)
        for entry in ql:
            _emit(f"    {entry}", f)
        _emit("\n  Forensic Significance (indirect): QuickLook caches file previews.", f)
        _emit("  Parse the SQLite DB with DB Browser for SQLite to confirm file previews.", f)
    else:
        _emit("  What was found: QuickLook cache not located.", f)

    # Section 9: Timeline
    _emit(f"\n{SEP}", f)
    _emit("                     CHRONOLOGICAL TIMELINE", f)
    _emit(SEP, f)
    col1 = 28
    col2 = 25
    header = f"{'TIMESTAMP':<{col1}} {'EVENT_TYPE':<{col2}} DETAIL"
    _emit(header, f)
    _emit(THIN, f)
    for e in evidence.get("timeline", []):
        ts = e["timestamp_str"][:col1 - 1]
        etype = e["event_type"][:col2 - 1]
        detail = e["detail"][:REPORT_WIDTH - col1 - col2 - 2]
        _emit(f"{ts:<{col1}} {etype:<{col2}} {detail}", f)

    # Section 10: Summary
    _emit(f"\n{SEP}", f)
    _emit("                       FORENSIC SUMMARY", f)
    _emit(SEP, f)
    _emit("  [Fill in after reviewing the sections above. Address:]", f)
    _emit("  - Which USB device was identified and when was it connected?", f)
    _emit("  - Which files show access timestamps within the USB window?", f)
    _emit("  - What does shell history or Finder destinations confirm?", f)
    _emit("  - What is your overall confidence that data was exfiltrated?", f)
    _emit("  - What are the limitations of this evidence?", f)
    _emit(SEP, f)
    _emit(f"\n  Report generated: {collected_at}", f)


# ---------------------------------------------------------------------------
# CSV timeline export
# ---------------------------------------------------------------------------

def write_csv_timeline(evidence: dict, path: Path) -> None:
    fieldnames = ["timestamp", "event_type", "detail", "source", "confidence"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for e in evidence.get("timeline", []):
            writer.writerow({
                "timestamp": e["timestamp_str"],
                "event_type": e["event_type"],
                "detail": e["detail"],
                "source": e["source"],
                "confidence": e["confidence"],
            })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="macOS USB forensics analysis script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "subcommand",
        nargs="?",
        choices=["collect", "timeline", "report"],
        help="collect=gather only; timeline=print timeline; report=full report from cache",
    )
    p.add_argument("--target", default=DEFAULT_TARGET,
                   help="Path of folder to analyze for file metadata")
    p.add_argument("--hours", type=int, default=DEFAULT_HOURS,
                   help="How many hours back to search unified log (default: 24)")
    p.add_argument("--output", default=None,
                   help="Write report to this file path in addition to stdout")
    return p.parse_args()


def collect_all(target: Path, hours: int) -> dict:
    evidence = {
        "collected_at": datetime.now().astimezone().isoformat(),
        "target_folder": str(target),
        "hours_back": hours,
    }
    evidence["usb_log_events"] = collect_usb_log_events(hours)
    evidence["disk_events"] = collect_disk_events(hours)
    evidence["usb_devices"] = collect_usb_devices()
    evidence["file_metadata"] = collect_file_metadata(target)
    evidence["finder_destinations"] = collect_finder_destinations()
    evidence["shell_history"] = collect_shell_history()
    evidence["ds_store_present"] = check_ds_store(target)
    evidence["quicklook_cache"] = check_quicklook_cache(target)
    evidence["timeline"] = build_timeline(evidence)
    return evidence


def main() -> None:
    if platform.system() != "Darwin":
        sys.exit("Error: usb_forensics.py requires macOS.")

    args = parse_args()
    target = Path(args.target).expanduser().resolve()
    out_path = Path(args.output).expanduser().resolve() if args.output else None

    sub = args.subcommand

    if sub == "timeline":
        if not CACHE_FILE.exists():
            sys.exit(f"No cache found at {CACHE_FILE}. Run 'collect' first.")
        evidence = json.loads(CACHE_FILE.read_text())
        for e in evidence.get("timeline", []):
            print(f"{e['timestamp_str']:<28} {e['event_type']:<25} {e['detail'][:40]}")
        return

    if sub == "report":
        if not CACHE_FILE.exists():
            sys.exit(f"No cache found at {CACHE_FILE}. Run 'collect' first.")
        evidence = json.loads(CACHE_FILE.read_text())
    else:
        evidence = collect_all(target, args.hours)
        if sub == "collect":
            CACHE_FILE.write_text(json.dumps(evidence, default=str))
            print(f"\n[+] Evidence saved to {CACHE_FILE}")
            print(f"    USB events : {len(evidence['usb_log_events'])}")
            print(f"    Disk events: {len(evidence['disk_events'])}")
            print(f"    Files      : {len(evidence['file_metadata'])}")
            print(f"    History    : {len(evidence['shell_history'])}")
            return

    print()
    format_report(evidence, out_path)

    csv_path = (out_path.parent / "timeline.csv") if out_path else Path("timeline.csv")
    write_csv_timeline(evidence, csv_path)
    print(f"\n[+] Timeline CSV written to: {csv_path}")
    if out_path:
        print(f"[+] Report written to     : {out_path}")


if __name__ == "__main__":
    main()
