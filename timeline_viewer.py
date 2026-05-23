#!/usr/bin/env python3
"""
timeline_viewer.py — Reads timeline.csv and generates a self-contained HTML
file (timeline_viewer.html) with interactive collapsible dropdowns organised
by source, then by event_type.  Data is preserved exactly as it appears in
the CSV; nothing is renamed or omitted.

Usage:
    python timeline_viewer.py                          # reads timeline.csv, writes timeline_viewer.html
    python timeline_viewer.py --csv my_timeline.csv    # custom input
    python timeline_viewer.py --out report.html        # custom output
"""

import argparse
import csv
import html
import json
import sys
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------
def load_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    if not rows:
        sys.exit(f"[!] No rows found in {path}")
    required = {"timestamp", "event_type", "detail", "source", "confidence"}
    missing = required - set(rows[0].keys())
    if missing:
        sys.exit(f"[!] CSV is missing columns: {missing}")
    return rows


def group_data(rows: list[dict]) -> dict:
    """
    Returns:
        {
          source: {
            event_type: [row, ...]
          }
        }
    All values are in original CSV order within each bucket.
    """
    grouped: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        grouped[row["source"]][row["event_type"]].append(row)
    return grouped


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------
SOURCE_COLORS = {
    "usb_log":       "#4f9cf9",
    "disk_log":      "#f97316",
    "file_metadata": "#22c55e",
    "shell_history": "#a78bfa",
    "finder_prefs":  "#f43f5e",
}

CONFIDENCE_TONES = {
    "high":   ("#166534", "#dcfce7"),   # green
    "medium": ("#92400e", "#fef3c7"),   # amber
    "low":    ("#991b1b", "#fee2e2"),   # red
}


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def _confidence_badge(conf: str) -> str:
    fg, bg = CONFIDENCE_TONES.get(conf, ("#374151", "#f3f4f6"))
    return (
        f'<span style="background:{bg};color:{fg};font-size:11px;'
        f'padding:1px 6px;border-radius:10px;font-weight:600;">'
        f'{_esc(conf)}</span>'
    )


def render_table(rows: list[dict]) -> str:
    headers = ["#", "Timestamp", "Event Type", "Detail", "Confidence"]
    col_widths = ["40px", "190px", "200px", "auto", "90px"]
    col_aligns = ["center", "left", "left", "left", "center"]

    header_cells = "".join(
        f'<th style="width:{w};text-align:{a};white-space:nowrap;'
        f'padding:6px 10px;border-bottom:2px solid #e5e7eb;'
        f'font-size:12px;color:#6b7280;font-weight:600;">{h}</th>'
        for h, w, a in zip(headers, col_widths, col_aligns)
    )

    body_rows = []
    for i, row in enumerate(rows):
        bg = "#ffffff" if i % 2 == 0 else "#f9fafb"
        body_rows.append(
            f'<tr style="background:{bg};">'
            f'<td style="text-align:center;padding:5px 10px;font-size:12px;'
            f'color:#9ca3af;">{i + 1}</td>'
            f'<td style="padding:5px 10px;font-size:12px;font-family:monospace;'
            f'white-space:nowrap;color:#374151;">{_esc(row["timestamp"])}</td>'
            f'<td style="padding:5px 10px;font-size:12px;white-space:nowrap;'
            f'color:#374151;">{_esc(row["event_type"])}</td>'
            f'<td style="padding:5px 10px;font-size:12px;color:#374151;'
            f'word-break:break-word;max-width:500px;">{_esc(row["detail"])}</td>'
            f'<td style="padding:5px 10px;text-align:center;">'
            f'{_confidence_badge(row["confidence"])}</td>'
            f'</tr>'
        )

    return (
        '<div style="overflow-x:auto;">'
        '<table style="width:100%;border-collapse:collapse;font-size:13px;">'
        f'<thead><tr>{header_cells}</tr></thead>'
        f'<tbody>{"".join(body_rows)}</tbody>'
        '</table></div>'
    )


def render_event_section(event_type: str, rows: list[dict], idx: int) -> str:
    count = len(rows)
    table_id = f"tbl_{idx}"
    toggle_id = f"tog_{idx}"
    table_html = render_table(rows)

    return f"""
<div style="margin-bottom:8px;">
  <button
    onclick="toggleSection('{table_id}', '{toggle_id}')"
    style="width:100%;text-align:left;background:#f3f4f6;border:1px solid #e5e7eb;
           border-radius:6px;padding:8px 12px;cursor:pointer;display:flex;
           align-items:center;gap:8px;font-size:13px;font-weight:500;color:#374151;"
  >
    <span id="{toggle_id}" style="font-size:10px;transition:transform .15s;">&#9654;</span>
    <span style="flex:1;">{_esc(event_type)}</span>
    <span style="background:#e5e7eb;color:#6b7280;font-size:11px;
                 padding:1px 8px;border-radius:10px;font-weight:600;">{count:,}</span>
  </button>
  <div id="{table_id}" style="display:none;margin-top:4px;border:1px solid #e5e7eb;
       border-radius:0 0 6px 6px;overflow:hidden;">
    {table_html}
  </div>
</div>
"""


def render_source_section(
    source: str,
    event_map: dict,
    source_idx: int,
    section_counter: list,
) -> str:
    color = SOURCE_COLORS.get(source, "#6b7280")
    total = sum(len(v) for v in event_map.values())
    src_body_id = f"src_{source_idx}"
    src_chev_id = f"srcchev_{source_idx}"

    inner_parts = []
    for event_type, rows in sorted(event_map.items()):
        section_counter[0] += 1
        inner_parts.append(render_event_section(event_type, rows, section_counter[0]))

    inner_html = "\n".join(inner_parts)

    return f"""
<div style="margin-bottom:12px;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
  <button
    onclick="toggleSection('{src_body_id}', '{src_chev_id}')"
    style="width:100%;text-align:left;background:#fff;border:none;padding:14px 16px;
           cursor:pointer;display:flex;align-items:center;gap:12px;"
  >
    <span id="{src_chev_id}"
          style="font-size:12px;color:{color};transition:transform .15s;">&#9654;</span>
    <span style="width:12px;height:12px;border-radius:3px;background:{color};
                 flex-shrink:0;"></span>
    <span style="flex:1;font-size:15px;font-weight:600;color:#111827;">{_esc(source)}</span>
    <span style="background:{color}22;color:{color};font-size:12px;
                 padding:2px 10px;border-radius:12px;font-weight:700;">{total:,} rows</span>
    <span style="font-size:12px;color:#9ca3af;margin-left:4px;">
      {len(event_map)} event type{'s' if len(event_map) != 1 else ''}
    </span>
  </button>
  <div id="{src_body_id}" style="display:none;padding:12px 16px 12px 16px;
       border-top:1px solid #f3f4f6;">
    {inner_html}
  </div>
</div>
"""


def render_stats_bar(grouped: dict, total: int) -> str:
    cards = []
    for source, event_map in sorted(grouped.items()):
        color = SOURCE_COLORS.get(source, "#6b7280")
        count = sum(len(v) for v in event_map.values())
        pct = count / total * 100
        cards.append(
            f'<div style="flex:1;min-width:140px;border:1px solid #e5e7eb;'
            f'border-radius:8px;padding:12px 16px;">'
            f'<div style="font-size:11px;color:#6b7280;font-weight:600;'
            f'text-transform:uppercase;letter-spacing:.05em;">{_esc(source)}</div>'
            f'<div style="font-size:24px;font-weight:700;color:{color};margin:4px 0;">'
            f'{count:,}</div>'
            f'<div style="height:4px;background:#f3f4f6;border-radius:2px;margin-top:6px;">'
            f'<div style="height:4px;background:{color};border-radius:2px;'
            f'width:{pct:.1f}%;"></div></div>'
            f'<div style="font-size:11px;color:#9ca3af;margin-top:4px;">{pct:.1f}% of total</div>'
            f'</div>'
        )
    return (
        '<div style="display:flex;flex-wrap:wrap;gap:12px;margin-bottom:24px;">'
        + "".join(cards)
        + "</div>"
    )


def render_search_bar() -> str:
    return """
<div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;">
  <input
    id="searchInput"
    type="text"
    placeholder="Filter by keyword across all sources..."
    oninput="filterRows(this.value)"
    style="flex:1;padding:8px 12px;border:1px solid #d1d5db;border-radius:6px;
           font-size:13px;outline:none;"
  />
  <button onclick="document.getElementById('searchInput').value='';filterRows('')"
          style="padding:8px 14px;background:#f3f4f6;border:1px solid #d1d5db;
                 border-radius:6px;font-size:13px;cursor:pointer;color:#374151;">
    Clear
  </button>
  <span id="matchCount" style="font-size:12px;color:#9ca3af;white-space:nowrap;"></span>
</div>
"""


JAVASCRIPT = """
function toggleSection(bodyId, chevId) {
  const body = document.getElementById(bodyId);
  const chev = document.getElementById(chevId);
  const isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : 'block';
  chev.style.transform = isOpen ? '' : 'rotate(90deg)';
}

function filterRows(query) {
  const q = query.trim().toLowerCase();
  const allRows = document.querySelectorAll('tbody tr');
  let matchCount = 0;
  allRows.forEach(tr => {
    const text = tr.textContent.toLowerCase();
    const visible = !q || text.includes(q);
    tr.style.display = visible ? '' : 'none';
    if (visible) matchCount++;
  });
  const countEl = document.getElementById('matchCount');
  if (q) {
    countEl.textContent = matchCount.toLocaleString() + ' row' + (matchCount !== 1 ? 's' : '') + ' matched';
  } else {
    countEl.textContent = '';
  }
}

function expandAll() {
  document.querySelectorAll('[id^="src_"], [id^="tbl_"]').forEach(el => {
    el.style.display = 'block';
  });
  document.querySelectorAll('[id^="srcchev_"], [id^="tog_"]').forEach(el => {
    el.style.transform = 'rotate(90deg)';
  });
}

function collapseAll() {
  document.querySelectorAll('[id^="src_"], [id^="tbl_"]').forEach(el => {
    el.style.display = 'none';
  });
  document.querySelectorAll('[id^="srcchev_"], [id^="tog_"]').forEach(el => {
    el.style.transform = '';
  });
}
"""


def build_html(rows: list[dict], grouped: dict, csv_path: Path) -> str:
    total = len(rows)
    from datetime import datetime
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    stats_html = render_stats_bar(grouped, total)
    search_html = render_search_bar()

    counter = [0]
    source_sections = []
    for i, (source, event_map) in enumerate(sorted(grouped.items())):
        source_sections.append(render_source_section(source, event_map, i, counter))

    sections_html = "\n".join(source_sections)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>USB Forensics Timeline Viewer</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f9fafb;
      color: #111827;
      padding: 32px 24px;
      max-width: 1200px;
      margin: 0 auto;
    }}
    button {{ font-family: inherit; }}
    input:focus {{ border-color: #4f9cf9 !important; }}
  </style>
</head>
<body>
  <div style="margin-bottom:28px;">
    <h1 style="font-size:22px;font-weight:700;color:#111827;">
      USB Forensics &mdash; Timeline Viewer
    </h1>
    <p style="font-size:13px;color:#6b7280;margin-top:4px;">
      Source: <code>{_esc(str(csv_path))}</code> &nbsp;&middot;&nbsp;
      {total:,} total rows &nbsp;&middot;&nbsp;
      Generated: {generated}
    </p>
  </div>

  {stats_html}

  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
    <h2 style="font-size:16px;font-weight:600;color:#374151;">Evidence by Source</h2>
    <div style="display:flex;gap:8px;">
      <button onclick="expandAll()"
              style="padding:6px 14px;background:#fff;border:1px solid #d1d5db;
                     border-radius:6px;font-size:12px;cursor:pointer;color:#374151;">
        Expand all
      </button>
      <button onclick="collapseAll()"
              style="padding:6px 14px;background:#fff;border:1px solid #d1d5db;
                     border-radius:6px;font-size:12px;cursor:pointer;color:#374151;">
        Collapse all
      </button>
    </div>
  </div>

  {search_html}
  {sections_html}

  <p style="margin-top:32px;font-size:11px;color:#d1d5db;text-align:center;">
    Data demographics unchanged &mdash; all {total:,} rows from {_esc(csv_path.name)} preserved verbatim.
  </p>

  <script>{JAVASCRIPT}</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate interactive HTML viewer from timeline CSV")
    p.add_argument(
        "--csv",
        default="timeline.csv",
        help="Path to the input CSV file (default: timeline.csv)",
    )
    p.add_argument(
        "--out",
        default="timeline_viewer.html",
        help="Path for the output HTML file (default: timeline_viewer.html)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    csv_path = Path(args.csv).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve()

    if not csv_path.exists():
        sys.exit(f"[!] CSV not found: {csv_path}")

    print(f"[*] Reading {csv_path}...")
    rows = load_csv(csv_path)
    print(f"[+] {len(rows):,} rows loaded")

    grouped = group_data(rows)
    sources = sorted(grouped.keys())
    print(f"[+] {len(sources)} sources: {', '.join(sources)}")
    for src in sources:
        total_src = sum(len(v) for v in grouped[src].values())
        event_types = sorted(grouped[src].keys())
        print(f"    {src}: {total_src} rows, {len(event_types)} event type(s): {', '.join(event_types)}")

    print(f"\n[*] Generating HTML...")
    html_content = build_html(rows, grouped, csv_path)
    out_path.write_text(html_content, encoding="utf-8")

    size_kb = out_path.stat().st_size / 1024
    print(f"[+] Written to: {out_path}  ({size_kb:.1f} KB)")
    print(f"\nOpen in your browser:")
    print(f"    open \"{out_path}\"")


if __name__ == "__main__":
    main()
