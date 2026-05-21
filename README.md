# macOS USB Device Forensics
### CS 480 — Special Topics: Digital Forensics | Vraj Soni | UMass Boston | Spring 2026

A hands-on digital forensics project that simulates an unauthorized file copy to a USB drive on macOS, then reconstructs the incident entirely from artifacts left on the host machine — no third-party tools required.

---

## What This Project Does

This project answers one forensic question:

> **Can a USB connection, a file-copy event, and the removal of the device be reconstructed from artifacts left on a macOS system?**

It simulates a controlled incident — a student's private files are copied to a USB drive — then uses Python scripts to collect evidence from macOS system logs, file metadata, shell history, and Finder preferences to rebuild a timeline of what happened.

---

## Project Files

```
usb_forensics_project/
├── usb_demo_setup.py          # Step 1 — creates the fake confidential folder
├── usb_trace.py               # Step 2 — runs the forensic analysis
└── README>md                  # About the repository README file
```

---

## Requirements

- macOS (tested on macOS Tahoe 26.3.1)
- Python 3.9 or later
- No pip packages — stdlib only
- Terminal must have **Full Disk Access** enabled for `log show` to work
  - System Settings → Privacy & Security → Full Disk Access → add Terminal

---

## How to Run

### Step 1 — Create the demo environment

```bash
python usb_demo_setup.py
```

This creates `~/Desktop/UMass_Confidential/` with 7 fake student files:

| File | Simulates |
|------|-----------|
| `Financial_Aid_Award_Spring2026.xlsx` | Financial aid records |
| `UMass_Transcript_Spring2026_UNOFFICIAL.csv` | Academic transcript |
| `Official_Transcript_UMass_CONFIDENTIAL.pdf` | Official transcript (FERPA-protected) |
| `CS480_FinalProject_Draft_v3.pdf` | Unpublished project draft |
| `Research_Thesis_Raw_Data.csv` | Raw research experiment data |
| `Scholarship_Application_Private.zip` | Scholarship application package |
| `README_PRIVATE_DO_NOT_COPY.txt` | Privacy warning |

It also opens the folder in Finder, which causes macOS to write `.DS_Store` — a forensic artifact.

---

### Step 2 — Stage the incident

1. Insert a USB drive
2. Copy the folder to the USB:
   ```bash
   cp -r ~/Desktop/UMass_Confidential /Volumes/<USB_NAME>/
   ```
   Or drag and drop in Finder
3. Safely eject and remove the USB drive

---

### Step 3 — Run the forensic analysis

```bash
python usb_trace.py --target ~/Desktop/UMass_Confidential --hours 2
```

To also save the report to a file:

```bash
python usb_trace.py --target ~/Desktop/UMass_Confidential --hours 2 --output report.txt
```

#### Other modes

```bash
python usb_trace.py collect     # collect evidence only, save to cache
python usb_trace.py timeline    # print timeline from cached evidence
python usb_trace.py report      # generate full report from cached evidence
```

---

## What the Script Collects

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

---

## Example Output

```
================================================================================
              macOS USB FORENSIC ANALYSIS REPORT
================================================================================
  Case Number   : USB-2026-001
  Target Folder : /Users/student/Desktop/UMass_Confidential
  Log Window    : Last 2 hours
  macOS Version : 14.4.1
================================================================================

[2  USB CONNECTION EVENTS]
  2026-05-19 10:02:09  SanDisk DataTraveler 3.0 detected
  2026-05-19 10:02:13  /Volumes/SanDisk mounted
  2026-05-19 10:28:40  /Volumes/SanDisk unmounted
  2026-05-19 10:28:44  SanDisk DataTraveler 3.0 removed

[4  FILE METADATA ANALYSIS]
  File: Financial_Aid_Award_Spring2026.xlsx
    Accessed (atime): 2026-05-19T10:05:18  <-- DURING USB WINDOW

[6  SHELL HISTORY MATCHES]
  .zsh_history:1203  [2026-05-19T10:04:55]
    cp -r /Users/student/Desktop/UMass_Confidential /Volumes/SanDisk/
```

---

## Output Files

After running `usb_trace.py`, two files are produced:

- **`report.txt`** — full formatted forensic report (if `--output` is specified)
- **`timeline.csv`** — chronological event timeline with columns: `timestamp, event_type, detail, source, confidence`

---

## Forensic Artifacts Explained

| Artifact | What It Proves |
|----------|---------------|
| USB log events | When the device was connected and removed |
| Volume mount/unmount | When the USB became accessible for file operations |
| File `atime` updated during USB window | Files were read — consistent with a copy |
| Shell history `cp` command | Explicit evidence of the copy method and destination |
| Finder `RecentMoveAndCopyDestinations` | Finder recorded the USB as a copy destination |
| `.DS_Store` in source folder | Finder browsed the folder before copying |

---

## Limitations

- `atime` updates can be disabled on some macOS configurations (`noatime` mount option)
- Shell history may be incomplete if manually cleared, or if Finder drag-and-drop was used instead of Terminal
- macOS Unified Log retains data for approximately 7 days by default
- QuickLook cache analysis requires a SQLite tool (e.g., DB Browser for SQLite) — this script only confirms the cache exists
- This investigation only covers the source Mac; analyzing what is on the USB itself requires separate examination of the device

---

## Project Background

**Course:** CS 480 — Special Topics: Digital Forensics, Spring 2026, UMass Boston

**Topic chosen because:**
- Hands-on and original — not covered in class (class used tcpdump, Wireshark, dd, foremost, steghide, ADB, WinPMem, Ghidra)
- macOS-native artifact collection using only built-in commands
- No VM required — runs directly on any Mac
- Demonstrates multiple forensic artifact categories and timeline reconstruction

---

## License

For academic use only. All files in `UMass_Confidential/` are fake demonstration data.
