# USB Device Forensics and Activity Tracking on macOS

**CS 480 — Special Topics: Introduction to Digital Forensics, Spring 2026**  
University of Massachusetts Boston · Vraj Soni  
GitHub: [github.com/vrajpsoni/macos-usb-forensics](https://github.com/vrajpsoni/macos-usb-forensics)

A hands-on digital forensics project that simulates an unauthorized file copy to a USB drive on macOS, then reconstructs the incident entirely from artifacts left on the host machine — no third-party tools required.

---

## Executive Summary

This project investigates whether a USB device connection, a file-copy event, and the removal of the device can be reconstructed from artifacts left on a macOS host without using any third-party forensic tools. A controlled incident was simulated in which a folder of private student files (`UMass_Confidential`) was copied to a USB drive. A Python-based forensic analysis tool (`usb_trace.py`) was then used to collect evidence from eight macOS artifact sources and reconstruct a chronological timeline of the incident.

The investigation successfully confirmed the USB device identity, the exact connection and disconnection timestamps, which files were accessed and when, the shell command used to perform the copy, and the Finder preference entry recording the USB as a copy destination. All evidence was collected using only macOS built-in commands and the Python standard library — no external tools were required.

The project consists of three Python scripts run in sequence:

1. `usb_demo_setup.py` — prepares the demo environment  
2. `usb_trace.py` — collects macOS artifacts and exports `timeline.csv`  
3. `timeline_viewer.py` — generates `timeline_viewer.html` for interactive browser-based evidence review  

---

## Forensic Question

> **Can the connection of a USB device, the copying of specific files to that device, and the subsequent removal of the device be reconstructed from artifacts left on a macOS host using only built-in system tools?**

Secondary questions:

- What artifacts does macOS record, and how reliable are they?
- Can a precise incident timeline be built from multiple artifact sources?
- What are the limitations of this approach, and how could it be defeated?

---

## Project Files

```
macos-usb-forensics/
├── usb_demo_setup.py              # Step 1 — creates UMass_Confidential demo folder
├── usb_trace.py                   # Step 3 — forensic analysis script
├── timeline_viewer.py             # Step 4 — reads timeline.csv, writes timeline_viewer.html
├── timeline.csv                   # chronological evidence export (from usb_trace.py)
├── timeline_viewer.html           # interactive browser viewer (from timeline_viewer.py)
├── README.md
├── Project_Plan.txt
├── CS480_Final_Project_Report.docx
└── ASSETS/
    ├── storyboard/                # 12-scene presentation storyboard (PNG)
    ├── STORY.pdf
    └── storyboard.zip
```

---

## Requirements

- macOS (tested on macOS Tahoe 26.3.1)
- Python 3.9 or later
- No pip packages — stdlib only
- Terminal must have **Full Disk Access** enabled for `log show` to work  
  System Settings → Privacy & Security → Full Disk Access → add Terminal

---

## How to Run

The hands-on workflow follows four steps: prepare the demo folder, stage the USB copy incident, run the forensic analysis, and review the exported timeline in the browser.

### Step 1 — Environment Setup

```bash
python usb_demo_setup.py
```

This creates `~/Desktop/UMass_Confidential/` containing 7 fake student files:

| File | Simulates |
|------|-----------|
| `Financial_Aid_Award_Spring2026.xlsx` | Financial aid award letter |
| `UMass_Transcript_Spring2026_UNOFFICIAL.csv` | Unofficial academic transcript with GPA |
| `Official_Transcript_UMass_CONFIDENTIAL.pdf` | Official registrar transcript (FERPA-protected) |
| `CS480_FinalProject_Draft_v3.pdf` | Unpublished course project draft |
| `Research_Thesis_Raw_Data.csv` | Raw USB experiment data |
| `Scholarship_Application_Private.zip` | Scholarship application package |
| `README_PRIVATE_DO_NOT_COPY.txt` | Privacy warning with FERPA notice |

The script also opens the folder in Finder, which causes macOS to write a `.DS_Store` file — a forensic artifact confirming Finder browsed the directory.

### Step 2 — Staged Incident

1. Insert a USB drive (e.g. Kingston DataTraveler 3.0)
2. Copy the folder to the USB:
   ```bash
   cp -r ~/Desktop/UMass_Confidential /Volumes/KINGSTON/
   ```
   Or drag and drop in Finder
3. Verify the copy: `ls /Volumes/KINGSTON/`
4. Safely eject and remove the USB drive

### Step 3 — Forensic Analysis

Run after the USB is removed:

```bash
python usb_trace.py --target ~/Desktop/UMass_Confidential --hours 2 --output report.txt
```

The script collects all 8 evidence categories, builds a chronological timeline, and writes a formatted report to both the terminal and `report.txt`. A `timeline.csv` file is also generated automatically.

Other modes:

```bash
python usb_trace.py collect     # collect evidence only, save to cache
python usb_trace.py timeline    # print timeline from cached evidence
python usb_trace.py report      # generate full report from cached evidence
```

### Step 4 — Timeline Review

Once `timeline.csv` has been generated:

```bash
python timeline_viewer.py
open timeline_viewer.html
```

The viewer organizes every collected event into collapsible dropdowns grouped first by evidence source (`usb_log`, `disk_log`, `file_metadata`, `shell_history`, `finder_prefs`), then by `event_type` within each source. All CSV data is preserved verbatim. Features include per-source statistics cards, expand/collapse all controls, live keyword search, and color-coded confidence badges. The generated HTML runs offline in any browser with no external dependencies.

Custom paths:

```bash
python timeline_viewer.py --csv timeline.csv --out timeline_viewer.html
```

---

## Tools, Scripts, and Methods

### Student-Written Scripts

| Script | Purpose |
|--------|---------|
| `usb_demo_setup.py` | Creates the controlled demo environment with fake confidential student files |
| `usb_trace.py` | Main forensic analysis tool — collects 8 artifact categories, builds a timeline, and outputs a formatted report |
| `timeline_viewer.py` | Reads `timeline.csv` and generates a self-contained interactive HTML viewer (`timeline_viewer.html`) |

All three scripts are written in Python 3 using only the standard library (`subprocess`, `json`, `datetime`, `pathlib`, `csv`, `html`, `argparse`, `re`, `platform`). No pip packages are required.

### macOS Built-in Commands Used

| Command | Purpose |
|---------|---------|
| `log show` | Query the macOS Unified Log for USB and disk events |
| `system_profiler SPUSBDataType` | Retrieve USB device name, vendor ID, product ID, and serial number |
| `mdls` | Read Spotlight metadata including last-used dates and content type per file |
| `stat` | Read precise BSD file timestamps: birthtime, mtime, atime, ctime |
| `defaults read com.apple.finder` | Read Finder's recent copy/move destination preferences |
| Shell history files | Search `~/.zsh_history` and `~/.bash_history` for copy commands |

### Analysis Methods

- Unified Log querying using predicate filters targeting DiskArbitration and IOUSBDevice subsystems
- File timestamp analysis — comparing access times (`atime`) against the USB connection window
- Shell history parsing — supporting zsh extended format and bash timestamp format
- Finder preference inspection — reading `RecentMoveAndCopyDestinations` plist key
- Timeline reconstruction — merging and sorting all evidence across heterogeneous sources

---

## Evidence Collection

| # | Evidence Source | macOS Command Used |
|---|----------------|--------------------|
| 1 | USB device info (name, vendor ID, serial) | `system_profiler SPUSBDataType` |
| 2 | USB connect/disconnect events | `log show` (Unified Log) |
| 3 | Volume mount/unmount events | `log show` (Unified Log) |
| 4 | File timestamps and Spotlight metadata | `mdls` + `stat` |
| 5 | Finder recent copy/move destinations | `defaults read com.apple.finder` |
| 6 | Shell history for copy commands | `~/.zsh_history`, `~/.bash_history` |
| 7 | `.DS_Store` presence in source folder | `Path.exists()` |
| 8 | QuickLook thumbnail cache | `/var/folders/` |

### Key Findings (Sample Run)

| Category | Finding |
|----------|---------|
| USB device | Kingston DataTraveler 3.0, Vendor `0x0951`, Product `0x1666` |
| Connection window | 10:02:09 connect → 10:28:44 disconnect (26 min 35 sec) |
| Volume | `/Volumes/KINGSTON` mounted at 10:02:13 (FAT32), unmounted at 10:28:40 |
| Shell history | `cp -r .../UMass_Confidential /Volumes/KINGSTON/` at 10:04:55 |
| File access | All 7 files had `atime` updated between 10:05:18 and 10:05:25 |
| Finder prefs | `file:///Volumes/KINGSTON/` in recent copy destinations |
| `.DS_Store` | Present in source folder — Finder browsed before copy |

---

## Reconstructed Timeline

| Timestamp | Event Type | Source |
|-----------|------------|--------|
| 2026-04-10 10:02:09 | USB_DEVICE_CONNECT — Kingston DataTraveler 3.0 | Unified Log |
| 2026-04-10 10:02:10 | USB_LOG_EVENT — DiskArbitration: disk2 appeared | Unified Log |
| 2026-04-10 10:02:13 | VOLUME_MOUNT — /Volumes/KINGSTON mounted (FAT32) | Unified Log |
| 2026-04-10 10:04:55 | SHELL_COPY_CMD — `cp -r .../UMass_Confidential /Volumes/KINGSTON/` | Shell history |
| 2026-04-10 10:05:18–10:05:25 | FILE_ACCESSED — all 7 files (sequential) | mdls + stat |
| 2026-04-10 10:05:30 | SHELL_COPY_CMD — `ls /Volumes/KINGSTON/` | Shell history |
| 2026-04-10 10:28:40 | VOLUME_UNMOUNT — /Volumes/KINGSTON unmounted cleanly | Unified Log |
| 2026-04-10 10:28:43 | USB_LOG_EVENT — DiskArbitration: disk2 disappeared | Unified Log |
| 2026-04-10 10:28:44 | USB_DEVICE_DISCONNECT — Kingston DataTraveler 3.0 removed | Unified Log |
| TIMESTAMP_UNKNOWN | FINDER_DESTINATION — `file:///Volumes/KINGSTON/` | Finder prefs |

The file-copy operation itself took approximately 35 seconds (10:04:55 to 10:05:30).

---

## Sample Script Output

```
================================================================
         macOS USB FORENSIC ANALYSIS REPORT
================================================================
  Case Number   : USB-2026-001
  Target Folder : /Users/student/Desktop/UMass_Confidential
  Log Window    : Last 2 hours  |  macOS : 14.4.1
================================================================

[1  USB DEVICE INVENTORY]
    Device : Kingston DataTraveler 3.0
    Vendor : 0x0951  Product : 0x1666
    Serial : 001CC04B4E1BDE80B16F13C5

[2  USB CONNECTION EVENTS]
    10:02:09  Kingston DataTraveler 3.0 detected
    10:02:13  /Volumes/KINGSTON mounted (FAT32)
    10:28:40  /Volumes/KINGSTON unmounted
    10:28:44  Kingston DataTraveler 3.0 removed

[4  FILE METADATA - atime during USB window]
    10:05:18  Financial_Aid_Award_Spring2026.xlsx          <-- DURING USB WINDOW
    10:05:20  UMass_Transcript_Spring2026_UNOFFICIAL.csv   <-- DURING USB WINDOW
    10:05:21  Official_Transcript_UMass_CONFIDENTIAL.pdf   <-- DURING USB WINDOW
    10:05:22  CS480_FinalProject_Draft_v3.pdf              <-- DURING USB WINDOW
    10:05:23  Research_Thesis_Raw_Data.csv                 <-- DURING USB WINDOW
    10:05:24  Scholarship_Application_Private.zip          <-- DURING USB WINDOW
    10:05:25  README_PRIVATE_DO_NOT_COPY.txt               <-- DURING USB WINDOW

[6  SHELL HISTORY]
    10:04:55  cp -r /Users/student/Desktop/UMass_Confidential /Volumes/KINGSTON/
    10:05:30  ls /Volumes/KINGSTON/
```

---

## Analysis

Five independent artifact categories corroborate the same narrative:

- Unified Log confirms the device was physically connected and a volume was mounted
- Shell history provides direct evidence of the exact copy command, timestamp, and destination
- File access timestamps show all 7 files were read within a 7-second window during the USB connection period
- Finder preferences confirm the USB volume was a Finder copy destination
- `.DS_Store` confirms Finder rendered the source directory before the copy

**Most significant evidence:** The shell history entry directly names the operation (`cp -r`), the source path, the destination (`/Volumes/KINGSTON/`), and the timestamp (10:04:55).

**What this investigation cannot prove:**

- Whether the files remain on the USB device (requires physical examination of the drive)
- Whether the files were subsequently transmitted elsewhere from the USB
- Whether the copy was authorized — forensics establishes what happened, not intent

---

## Limitations

| Limitation | Impact |
|------------|--------|
| `atime` can be disabled with `noatime` mount option | File access timestamps unavailable — most significant evidence gap |
| Shell history can be manually cleared | `cp` command evidence disappears; only atime + Finder prefs remain |
| Unified Log retention is ~7 days by default | Evidence of events older than a week is lost |
| Finder drag-and-drop leaves no shell history | Shell history section returns empty |
| QuickLook SQLite DB requires external parser | File preview evidence not fully accessible from this script |
| Script only examines the source Mac | USB device contents require separate forensic acquisition |

---

## Key Functions

### `usb_trace.py`

| Function | Description |
|----------|-------------|
| `run_cmd(cmd, timeout)` | Safe subprocess wrapper — never raises, returns `(stdout, stderr, rc)` |
| `parse_log_output(raw)` | Parses `log show` output as JSON array or NDJSON fallback |
| `parse_timestamp(ts_str)` | Normalizes timestamps across 4 different macOS format variants |
| `collect_usb_log_events(hours)` | Queries Unified Log for USB/DiskArbitration events |
| `collect_disk_events(hours)` | Queries Unified Log for mount/unmount events |
| `collect_usb_devices()` | Parses `system_profiler` JSON, recursively walks hub nesting |
| `collect_file_metadata(folder)` | Runs `mdls` + `stat` per file, normalizes into unified dict |
| `collect_finder_destinations()` | Reads `com.apple.finder RecentMoveAndCopyDestinations` |
| `collect_shell_history()` | Parses zsh/bash history, filters for copy-related patterns |
| `check_ds_store(folder)` | Checks for `.DS_Store` presence |
| `check_quicklook_cache(folder)` | Searches `/var/folders/` for QuickLook cache directory |
| `build_timeline(evidence)` | Merges all sources into a sorted chronological event list |
| `format_report(evidence, outpath)` | Renders the full formatted report |
| `write_csv_timeline(evidence, path)` | Writes `timeline.csv` via `csv.DictWriter` |

### `timeline_viewer.py`

| Function | Description |
|----------|-------------|
| `load_csv(path)` | Validates required columns and loads all rows from `timeline.csv` |
| `group_data(rows)` | Nests rows by source, then `event_type`, preserving CSV order |
| `render_stats_bar(grouped, total)` | Builds per-source count and percentage statistics cards |
| `build_html(rows, grouped, csv_path)` | Assembles the self-contained HTML document with collapsible panels |
| `main()` | CLI entry point; reads CSV, prints source summary, writes HTML output |

---

## Lessons Learned

- macOS logs far more than users expect — the Unified Log captures USB enumeration, DiskArbitration events, and volume mounts with millisecond-resolution timestamps
- Convergence is the foundation of forensic confidence — no single artifact is conclusive on its own
- `atime` is a powerful but fragile indicator — broadly applicable for file access, but easy to disable
- Anti-forensics requires deliberate effort — clearing all artifact categories simultaneously requires knowledge and intent
- Forensic reconstruction is not the same as proof of intent

---

## License

For academic use only. All files in `UMass_Confidential/` are fake demonstration data.
