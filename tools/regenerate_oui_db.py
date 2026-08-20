#!/usr/bin/env python3
"""
regenerate_oui_db.py
---------------------
Regenerates include/oui_database.h from IEEE's public MA-L (24-bit OUI)
assignment registry.

Why this exists
---------------
ESP32WifiPhisher's Host Discovery resolves a MAC's vendor via a static,
sorted C array (oui_db[] in include/oui_database.h) that is bsearch()'d by
the top 24 bits of the MAC. The lookup code itself is correct - the problem
is that the shipped table only has ~23k entries and is missing many common,
legitimately-registered vendors (Amazon, TP-Link, Tuya, Tp-Link, Arcadyan,
Vodafone, Meross, etc. have all been confirmed present in IEEE's registry but
absent from the local table). Run this script to pull a fresh copy straight
from IEEE and rebuild the table in the exact same format/sort order the
existing bsearch() lookup expects.

This must be run from a machine with normal internet access (your PC), not
from a sandboxed environment - IEEE's server blocks common bot/sandbox
traffic (returns HTTP 418) and mirrors like Wireshark's gitlab/GitHub raw
files enforce robots.txt disallow rules that block scripted access too.
A regular browser or a plain requests call from your own machine works fine.

Usage
-----
    python3 regenerate_oui_db.py

    # Optional flags:
    python3 regenerate_oui_db.py --output ../include/oui_database.h
    python3 regenerate_oui_db.py --input path/to/already-downloaded/oui.csv
    python3 regenerate_oui_db.py --no-keep-existing

By default the script:
  1. Downloads https://standards-oui.ieee.org/oui/oui.csv (IEEE's official
     MA-L assignment list, ~24-bit OUIs - the same 24-bit granularity the
     existing oui_db[] structure uses, so no C-side restructuring needed).
  2. Parses "Assignment,Organization Name" out of the CSV.
  3. Also parses the *existing* include/oui_database.h (if found) and keeps
     any OUI entries from it that are missing from the fresh IEEE pull, so
     nothing already in the table is silently lost. Pass --no-keep-existing
     to disable this and do a clean rebuild from IEEE data only.
  4. Sorts everything by OUI ascending (required for bsearch() to work) and
     writes a new include/oui_database.h in the same format as the original.

Requires only the Python standard library (urllib, csv, re) - no pip
installs needed.
"""

import argparse
import csv
import io
import os
import re
import sys
import urllib.request

IEEE_OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"

HEADER = """/* Generato automaticamente - OUI Database */
#include <stdint.h>

typedef struct {
    uint32_t oui;
    const char *vendor;
} mac_oui_t;

// Array in Flash (RAM = 0)
static const mac_oui_t oui_db[] = {
"""

FOOTER = """};
"""


def fetch_ieee_csv(url):
    print(f"[*] Downloading {url} ...")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    text = data.decode("utf-8", errors="replace")
    print(f"[*] Downloaded {len(text):,} bytes")
    return text


def parse_ieee_csv(csv_text):
    """IEEE's oui.csv columns: Registry,Assignment,Organization Name,Organization Address"""
    entries = {}
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        assignment = (row.get("Assignment") or "").strip()
        vendor = (row.get("Organization Name") or "").strip()
        if not assignment or not vendor:
            continue
        try:
            oui = int(assignment, 16)
        except ValueError:
            continue
        if oui > 0xFFFFFF:
            continue  # only 24-bit MA-L blocks fit this table's format
        entries[oui] = sanitize_vendor(vendor)
    return entries


def sanitize_vendor(name):
    """Make a vendor string safe to embed as a C string literal."""
    # Collapse whitespace, strip control chars, escape backslash/quotes.
    name = re.sub(r"\s+", " ", name).strip()
    name = name.replace("\\", "\\\\").replace('"', '\\"')
    # Drop non-ASCII to avoid encoding surprises in the C source / on-device
    # rendering; keep it readable rather than perfectly lossless.
    name = name.encode("ascii", "ignore").decode("ascii")
    return name or "Unknown"


def parse_existing_header(path):
    """Best-effort parser for the current oui_database.h, used only to keep
    entries that would otherwise be lost if IEEE's feed doesn't cover them."""
    entries = {}
    if not os.path.isfile(path):
        return entries
    line_re = re.compile(r'\{\s*0x([0-9A-Fa-f]{6})\s*,\s*"((?:[^"\\]|\\.)*)"\s*\}')
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = line_re.search(line)
            if m:
                oui = int(m.group(1), 16)
                vendor = m.group(2)
                entries[oui] = vendor
    return entries


def write_header(entries, output_path):
    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(HEADER)
        for oui in sorted(entries.keys()):
            f.write('    { 0x%06X, "%s" },\n' % (oui, entries[oui]))
        f.write(FOOTER)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=IEEE_OUI_CSV_URL, help="IEEE MA-L CSV URL")
    ap.add_argument("--input", help="Use a local CSV file instead of downloading")
    ap.add_argument("--output", default=None,
                     help="Path to write oui_database.h (default: ../include/oui_database.h relative to this script)")
    ap.add_argument("--no-keep-existing", action="store_true",
                     help="Do not preserve OUIs from the current oui_database.h that are missing from IEEE's feed")
    args = ap.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = args.output or os.path.join(script_dir, "..", "include", "oui_database.h")
    output_path = os.path.abspath(output_path)

    if args.input:
        with open(args.input, "r", encoding="utf-8", errors="replace") as f:
            csv_text = f.read()
    else:
        try:
            csv_text = fetch_ieee_csv(args.url)
        except Exception as e:
            print(f"[!] Failed to download {args.url}: {e}", file=sys.stderr)
            print("[!] If IEEE is blocking automated requests, download the CSV manually", file=sys.stderr)
            print("    from https://standards-oui.ieee.org/oui/oui.csv in your browser and", file=sys.stderr)
            print("    re-run with --input <path-to-file>.", file=sys.stderr)
            sys.exit(1)

    fresh_entries = parse_ieee_csv(csv_text)
    print(f"[*] Parsed {len(fresh_entries):,} OUI entries from IEEE data")

    if not args.no_keep_existing:
        existing_entries = parse_existing_header(output_path)
        kept = 0
        for oui, vendor in existing_entries.items():
            if oui not in fresh_entries:
                fresh_entries[oui] = vendor
                kept += 1
        if kept:
            print(f"[*] Preserved {kept:,} entries from the existing table not present in the fresh IEEE pull")

    write_header(fresh_entries, output_path)
    print(f"[+] Wrote {len(fresh_entries):,} entries to {output_path}")
    print("[+] Done. Rebuild the firmware and re-flash SPIFFS/the app image as usual.")


if __name__ == "__main__":
    main()
