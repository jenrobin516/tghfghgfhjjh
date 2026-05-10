#!/usr/bin/env python3
"""
pe_analyzer.py — Windows PE (Portable Executable) File Analyzer
================================================================
Reverse-engineering utility that parses a PE binary and prints:
  • DOS / NT / Optional headers
  • Section table (name, VAs, sizes, characteristics)
  • Import table  (DLL names + imported functions)
  • Export table  (exported function names + RVAs)
  • Embedded printable strings (configurable minimum length)

Dependencies
------------
    pip install pefile

Usage
-----
    python pe_analyzer.py <path_to_pe> [--strings] [--min-len N]

Examples
--------
    python pe_analyzer.py notepad.exe
    python pe_analyzer.py malware_sample.dll --strings --min-len 6
"""

import argparse
import os
import string
import sys

try:
    import pefile
except ImportError:
    sys.exit(
        "[!] 'pefile' is not installed.  Run:  pip install pefile"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SECTION_FLAGS = {
    0x00000020: "CODE",
    0x00000040: "INITIALIZED_DATA",
    0x00000080: "UNINITIALIZED_DATA",
    0x02000000: "DISCARDABLE",
    0x10000000: "SHARED",
    0x20000000: "EXECUTE",
    0x40000000: "READ",
    0x80000000: "WRITE",
}


def flags_to_str(characteristics: int) -> str:
    active = [name for mask, name in SECTION_FLAGS.items() if characteristics & mask]
    return " | ".join(active) if active else hex(characteristics)


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Return all printable ASCII strings of at least *min_len* chars."""
    printable = set(string.printable) - set("\t\n\r\x0b\x0c")
    results, current = [], []
    for byte in data:
        ch = chr(byte)
        if ch in printable:
            current.append(ch)
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results


# ---------------------------------------------------------------------------
# Analysis sections
# ---------------------------------------------------------------------------

def print_header(pe: pefile.PE) -> None:
    print("\n" + "=" * 70)
    print("  FILE HEADERS")
    print("=" * 70)

    # DOS header
    print(f"\n[DOS Header]")
    print(f"  Magic              : {hex(pe.DOS_HEADER.e_magic)}")
    print(f"  e_lfanew (PE offset): {hex(pe.DOS_HEADER.e_lfanew)}")

    # NT / File header
    fh = pe.FILE_HEADER
    print(f"\n[NT File Header]")
    print(f"  Machine            : {hex(fh.Machine)}  ({pefile.MACHINE_TYPE.get(fh.Machine, 'Unknown')})")
    print(f"  Number of Sections : {fh.NumberOfSections}")
    print(f"  TimeDateStamp      : {fh.dump_dict()['TimeDateStamp']['Value']}")
    print(f"  Characteristics    : {hex(fh.Characteristics)}")

    # Optional header
    oh = pe.OPTIONAL_HEADER
    print(f"\n[Optional Header]")
    print(f"  Magic (arch)       : {hex(oh.Magic)}")
    print(f"  Entry Point (RVA)  : {hex(oh.AddressOfEntryPoint)}")
    print(f"  Image Base         : {hex(oh.ImageBase)}")
    print(f"  Section Alignment  : {hex(oh.SectionAlignment)}")
    print(f"  File Alignment     : {hex(oh.FileAlignment)}")
    print(f"  Size of Image      : {hex(oh.SizeOfImage)}")
    print(f"  Subsystem          : {oh.Subsystem}  ({pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, 'Unknown')})")


def print_sections(pe: pefile.PE) -> None:
    print("\n" + "=" * 70)
    print("  SECTIONS")
    print("=" * 70)
    fmt = "  {:<12} {:>10} {:>10} {:>10} {:>10}  {}"
    print(fmt.format("Name", "VirtAddr", "VirtSize", "RawAddr", "RawSize", "Flags"))
    print("  " + "-" * 68)
    for sec in pe.sections:
        name = sec.Name.decode(errors="replace").rstrip("\x00")
        print(fmt.format(
            name,
            hex(sec.VirtualAddress),
            hex(sec.Misc_VirtualSize),
            hex(sec.PointerToRawData),
            hex(sec.SizeOfRawData),
            flags_to_str(sec.Characteristics),
        ))


def print_imports(pe: pefile.PE) -> None:
    print("\n" + "=" * 70)
    print("  IMPORTS")
    print("=" * 70)
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        print("  (no import directory found)")
        return
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="replace")
        print(f"\n  [{dll}]")
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode(errors="replace")
            else:
                name = f"ordinal#{imp.ordinal}"
            print(f"    {hex(imp.address):>18}  {name}")


def print_exports(pe: pefile.PE) -> None:
    print("\n" + "=" * 70)
    print("  EXPORTS")
    print("=" * 70)
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        print("  (no export directory found)")
        return
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode(errors="replace") if exp.name else f"ordinal#{exp.ordinal}"
        print(f"  ordinal={exp.ordinal:<5}  rva={hex(exp.address):<12}  {name}")


def print_strings(pe: pefile.PE, min_len: int) -> None:
    print("\n" + "=" * 70)
    print(f"  STRINGS  (min length = {min_len})")
    print("=" * 70)
    found = extract_strings(pe.__data__, min_len)
    for s in found:
        print(f"  {s}")
    print(f"\n  Total strings found: {len(found)}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="PE file analyzer for reverse engineering.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("pe_file", help="Path to the PE file to analyze")
    parser.add_argument(
        "--strings", action="store_true", help="Also extract embedded printable strings"
    )
    parser.add_argument(
        "--min-len", type=int, default=4, metavar="N",
        help="Minimum string length for --strings (default: 4)"
    )
    args = parser.parse_args()

    if not os.path.isfile(args.pe_file):
        sys.exit(f"[!] File not found: {args.pe_file}")

    print(f"\n[*] Analyzing: {os.path.abspath(args.pe_file)}")
    print(f"[*] File size : {os.path.getsize(args.pe_file):,} bytes")

    try:
        pe = pefile.PE(args.pe_file)
    except pefile.PEFormatError as exc:
        sys.exit(f"[!] Not a valid PE file: {exc}")

    print_header(pe)
    print_sections(pe)
    print_imports(pe)
    print_exports(pe)

    if args.strings:
        print_strings(pe, args.min_len)

    print("\n[*] Analysis complete.\n")


if __name__ == "__main__":
    main()
