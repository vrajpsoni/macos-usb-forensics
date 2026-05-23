#!/usr/bin/env python3
"""
usb_demo_setup.py — Creates a fake "UMass_Confidential" folder on the Mac
desktop for the USB forensics demonstration. Run this once before the staged
incident.

Usage:
    python usb_demo_setup.py [--path ~/Desktop/MyFolder] [--no-finder]
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# File specs: each has a name, binary content, and a short description
# ---------------------------------------------------------------------------
def _build_file_specs() -> list[dict]:
    png_magic = b"\x89PNG\r\n\x1a\n" + b"\x00" * 256
    zip_magic = b"PK\x03\x04" + b"\x00" * 256
    transcript_pdf = (
        "%PDF-1.4\n"
        "1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        "% University of Massachusetts Amherst\n"
        "% Office of the Registrar — Official Academic Transcript\n"
        "% Student: [REDACTED FOR DEMO]\n"
        "% CONFIDENTIAL — For authorized recipients only\n"
        "% Do not copy or distribute without written consent\n"
    )
    thesis_pdf = (
        "%PDF-1.4\n"
        "1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        "% CS 480 Special Topics — Digital Forensics\n"
        "% Final Project Report — DRAFT\n"
        "% USB Device Forensics and Activity Tracking on macOS\n"
        "% UMass Amherst, Spring 2026\n"
        "% STATUS: DO NOT DISTRIBUTE — unpublished student work\n"
    )

    return [
        {
            "name": "Financial_Aid_Award_Spring2026.xlsx",
            "content": (
                "Aid_Type,Award_Amount,Disbursement_Date,Status,Account_Balance\n"
                "Federal Pell Grant,3450.00,2026-01-15,Disbursed,0.00\n"
                "UMass Need-Based Grant,5200.00,2026-01-15,Disbursed,0.00\n"
                "Subsidized Stafford Loan,3500.00,2026-01-20,Disbursed,0.00\n"
                "Unsubsidized Stafford Loan,2000.00,2026-01-20,Disbursed,0.00\n"
                "Work-Study Award,2400.00,2026-05-01,Pending,2400.00\n"
                "TOTAL AWARD,16550.00,,Mixed,2400.00\n"
            ).encode(),
            "description": "Financial aid award letter for Spring 2026",
        },
        {
            "name": "UMass_Transcript_Spring2026_UNOFFICIAL.csv",
            "content": (
                "Term,Course,Title,Credits,Grade,GPA_Points\n"
                "Spring 2026,CS 480,Special Topics: Digital Forensics,3,A,4.0\n"
                "Spring 2026,CS 446,Search Engines,3,A-,3.7\n"
                "Spring 2026,MATH 411,Introduction to Abstract Algebra,3,B+,3.3\n"
                "Fall 2025,CS 377,Operating Systems,3,A,4.0\n"
                "Fall 2025,CS 345,Practice and Applications of Data Mgmt,3,A-,3.7\n"
                "Fall 2025,CS 325,Algorithm Design,3,B+,3.3\n"
                "Cumulative GPA,,,,,3.72\n"
            ).encode(),
            "description": "Unofficial academic transcript with current GPA",
        },
        {
            "name": "Official_Transcript_UMass_CONFIDENTIAL.pdf",
            "content": transcript_pdf.encode(),
            "description": "Official academic transcript PDF (fake PDF header)",
        },
        {
            "name": "CS480_FinalProject_Draft_v3.pdf",
            "content": thesis_pdf.encode(),
            "description": "CS 480 final project report draft (fake PDF header)",
        },
        {
            "name": "Research_Thesis_Raw_Data.csv",
            "content": (
                "ExperimentID,Timestamp,USB_EventType,Device_Serial,VolumeName,FileCopied,ATime_Updated\n"
                "EXP-001,2026-04-10T10:02:11,CONNECT,ABC12345DEF,KINGSTON,FALSE,FALSE\n"
                "EXP-001,2026-04-10T10:02:14,MOUNT,ABC12345DEF,KINGSTON,FALSE,FALSE\n"
                "EXP-001,2026-04-10T10:05:33,FILE_COPY,ABC12345DEF,KINGSTON,TRUE,TRUE\n"
                "EXP-001,2026-04-10T10:07:48,UNMOUNT,ABC12345DEF,KINGSTON,FALSE,FALSE\n"
                "EXP-001,2026-04-10T10:07:50,DISCONNECT,ABC12345DEF,KINGSTON,FALSE,FALSE\n"
            ).encode(),
            "description": "Raw experiment data collected for thesis research",
        },
        {
            "name": "Scholarship_Application_Private.zip",
            "content": zip_magic,
            "description": "Scholarship application package (fake ZIP header)",
        },
        {
            "name": "README_PRIVATE_DO_NOT_COPY.txt",
            "content": (
                "UMASS AMHERST — STUDENT PRIVATE FILES\n"
                "======================================\n\n"
                "This folder contains private student academic and financial records.\n"
                "Unauthorized access, copying, or distribution of these files may\n"
                "violate FERPA (Family Educational Rights and Privacy Act) and\n"
                "UMass Amherst student data privacy policies.\n\n"
                "Owner: [Student Name]\n"
                "SPIRE ID: [REDACTED FOR DEMO]\n\n"
                "If you have accessed this folder in error, contact the UMass\n"
                "Registrar or IT Security immediately.\n"
            ).encode(),
            "description": "Privacy warning notice referencing FERPA",
        },
    ]


def create_demo_folder(base_path: Path) -> Path:
    folder = base_path / "UMass_Confidential"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def write_fake_files(folder: Path) -> list[dict]:
    specs = _build_file_specs()
    created = []
    for spec in specs:
        target = folder / spec["name"]
        target.write_bytes(spec["content"])
        created.append({"path": target, "name": spec["name"], "description": spec["description"]})
        print(f"  [+] {spec['name']}  ({len(spec['content'])} bytes)")
    return created


def touch_files_with_finder(folder: Path) -> None:
    """Open the folder in Finder so macOS writes .DS_Store (a forensic artifact)."""
    print("\n[*] Opening folder in Finder to generate .DS_Store artifact...")
    subprocess.run(["open", str(folder)], check=False)
    time.sleep(2)
    input("    Press Enter after Finder has opened the folder to continue... ")
    # Close the Finder window via AppleScript
    subprocess.run(
        ["osascript", "-e", 'tell application "Finder" to close every window'],
        check=False,
    )
    ds_store = folder / ".DS_Store"
    if ds_store.exists():
        print("  [+] .DS_Store created by Finder — forensic artifact confirmed")
    else:
        print("  [!] .DS_Store not yet written — try opening the folder manually in Finder")


def print_summary(folder: Path, files: list[dict]) -> None:
    width = 70
    print("\n" + "=" * width)
    print("  DEMO SETUP COMPLETE")
    print("=" * width)
    print(f"  Folder : {folder}")
    print(f"  Files  : {len(files)}")
    print("-" * width)
    for f in files:
        print(f"  {f['name']:<45} {f['description']}")
    print("=" * width)
    print()
    print("Next steps:")
    print("  1. Insert a USB drive into the Mac")
    print("  2. Open Finder, navigate to the UMass_Confidential folder")
    print("  3. Copy one or more files to the USB drive manually")
    print("     (or run:  cp -r <folder> /Volumes/<USB_NAME>/)")
    print("  4. Safely eject and remove the USB drive")
    print("  5. Run:  python usb_trace.py --target", folder)
    print()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Create USB forensics demo environment")
    p.add_argument(
        "--path",
        default=str(Path.home() / "Desktop"),
        help="Parent directory for the demo folder (default: ~/Desktop)",
    )
    p.add_argument(
        "--no-finder",
        action="store_true",
        help="Skip opening the folder in Finder (skip .DS_Store generation)",
    )
    return p.parse_args()


def main() -> None:
    if sys.platform != "darwin":
        sys.exit("Error: usb_demo_setup.py is designed for macOS only.")

    args = parse_args()
    base = Path(args.path).expanduser().resolve()

    print(f"\n[*] Creating demo folder inside: {base}")
    folder = create_demo_folder(base)
    print(f"[+] Folder: {folder}\n")

    print("[*] Writing fake confidential files...")
    files = write_fake_files(folder)

    if not args.no_finder:
        touch_files_with_finder(folder)

    print_summary(folder, files)


if __name__ == "__main__":
    main()
