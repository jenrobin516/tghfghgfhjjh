#!/usr/bin/env python3
"""
disasm_dump.py — Binary Disassembler / Code Dump Utility
=========================================================
Reverse-engineering utility that disassembles raw binary data or a
PE/ELF executable using the Capstone disassembly engine and prints
annotated assembly output.

Features
--------
  • Auto-detects x86 (32-bit) vs x86-64 from a PE optional header,
    or lets you specify the architecture manually.
  • Disassembles the .text / CODE section of a PE file automatically.
  • Can also disassemble arbitrary raw bytes (shellcode, firmware, etc.).
  • Highlights potential "interesting" instructions: calls, jumps, int 0x80,
    syscall, ret — for quick triage during RE sessions.
  • Optionally limits output to a byte-offset range within the file.

Dependencies
------------
    pip install capstone pefile

Usage
-----
    # Disassemble the .text section of a PE:
    python disasm_dump.py calc.exe

    # Disassemble raw shellcode (x64):
    python disasm_dump.py shellcode.bin --raw --arch x64

    # Disassemble only bytes 0x400–0x800 of a file (raw mode):
    python disasm_dump.py firmware.bin --raw --offset 0x400 --length 0x400

    # Disassemble PE .text section, show only first 200 instructions:
    python disasm_dump.py malware.exe --limit 200
"""

import argparse
import os
import sys

try:
    import capstone
except ImportError:
    sys.exit("[!] 'capstone' is not installed.  Run:  pip install capstone")

try:
    import pefile
except ImportError:
    pefile = None  # optional for raw-mode usage


# ---------------------------------------------------------------------------
# Architecture helpers
# ---------------------------------------------------------------------------

ARCH_MAP = {
    "x86":   (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
    "x64":   (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
    "arm":   (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
    "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    "mips":  (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN),
}

# PE machine-type → arch string
PE_MACHINE_ARCH = {
    0x014C: "x86",   # IMAGE_FILE_MACHINE_I386
    0x8664: "x64",   # IMAGE_FILE_MACHINE_AMD64
    0x01C0: "arm",   # IMAGE_FILE_MACHINE_ARM
    0xAA64: "arm64", # IMAGE_FILE_MACHINE_ARM64
}

# Instructions worth highlighting during triage
HIGHLIGHT_MNEMONICS = {
    "call", "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno", "jp", "jnp",
    "ret", "retn", "retf", "syscall", "sysenter", "int",
}

RESET   = "\033[0m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
BOLD    = "\033[1m"


def colorize(mnemonic: str, line: str, use_color: bool) -> str:
    if not use_color:
        return line
    mnem_lower = mnemonic.lower()
    if mnem_lower == "ret" or mnem_lower.startswith("ret"):
        return GREEN + line + RESET
    if mnem_lower == "call":
        return YELLOW + line + RESET
    if mnem_lower.startswith("j"):
        return CYAN + line + RESET
    if mnem_lower in ("syscall", "sysenter", "int"):
        return BOLD + line + RESET
    return line


# ---------------------------------------------------------------------------
# PE helpers
# ---------------------------------------------------------------------------

def load_pe_text_section(path: str) -> tuple[bytes, int, str]:
    """
    Return (code_bytes, load_va, arch_str) for the first executable
    section found in a PE file.
    """
    if pefile is None:
        sys.exit("[!] 'pefile' is required for PE mode.  Run:  pip install pefile")
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError as exc:
        sys.exit(f"[!] Not a valid PE file: {exc}")

    machine = pe.FILE_HEADER.Machine
    arch = PE_MACHINE_ARCH.get(machine, "x64")

    # Find first section with EXECUTE characteristic
    EXEC_FLAG = 0x20000000
    for sec in pe.sections:
        if sec.Characteristics & EXEC_FLAG:
            va = pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
            data = sec.get_data()
            name = sec.Name.decode(errors="replace").rstrip("\x00")
            print(f"[*] Disassembling section '{name}'  VA={hex(va)}  size={len(data):,} bytes")
            return data, va, arch

    sys.exit("[!] No executable section found in PE.  Try --raw mode.")


# ---------------------------------------------------------------------------
# Core disassembly
# ---------------------------------------------------------------------------

def disassemble(
    data: bytes,
    base_addr: int,
    arch: str,
    limit: int,
    use_color: bool,
) -> None:
    if arch not in ARCH_MAP:
        sys.exit(f"[!] Unknown architecture '{arch}'.  Choose from: {', '.join(ARCH_MAP)}")

    cs_arch, cs_mode = ARCH_MAP[arch]
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = False

    count = 0
    print(f"\n{'Offset':>10}  {'Address':>18}  {'Bytes':<24}  {'Mnemonic':<10}  Operands")
    print("-" * 80)

    file_offset = 0
    for insn in md.disasm(data, base_addr):
        if limit and count >= limit:
            print(f"\n[*] Output limited to {limit} instructions (use --limit 0 for all).")
            break

        raw_bytes = " ".join(f"{b:02x}" for b in insn.bytes)
        line = (
            f"{file_offset:>10}  {insn.address:#018x}  {raw_bytes:<24}  "
            f"{insn.mnemonic:<10}  {insn.op_str}"
        )
        print(colorize(insn.mnemonic, line, use_color))
        file_offset += len(insn.bytes)
        count += 1

    print(f"\n[*] Total instructions disassembled: {count}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Binary disassembler for reverse engineering.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("file", help="Binary file to disassemble")
    parser.add_argument(
        "--raw", action="store_true",
        help="Treat the file as raw shellcode / firmware (skip PE parsing)",
    )
    parser.add_argument(
        "--arch", default="x64", choices=list(ARCH_MAP),
        help="Target architecture (default: x64; auto-detected for PE files)",
    )
    parser.add_argument(
        "--offset", default="0",
        help="Start offset in file for --raw mode, hex or decimal (default: 0)",
    )
    parser.add_argument(
        "--length", default="0",
        help="Number of bytes to disassemble in --raw mode, 0 = all (default: 0)",
    )
    parser.add_argument(
        "--base", default=None,
        help="Override the base virtual address for display (hex or decimal)",
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Max number of instructions to print, 0 = unlimited (default: 0)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colour highlighting",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        sys.exit(f"[!] File not found: {args.file}")

    print(f"\n[*] File   : {os.path.abspath(args.file)}")
    print(f"[*] Size   : {os.path.getsize(args.file):,} bytes")

    use_color = not args.no_color and sys.stdout.isatty()

    if args.raw:
        offset = int(args.offset, 0)
        length = int(args.length, 0)
        with open(args.file, "rb") as fh:
            fh.seek(offset)
            data = fh.read(length) if length else fh.read()
        base_addr = int(args.base, 0) if args.base else 0x0
        arch = args.arch
        print(f"[*] Mode   : raw  offset={hex(offset)}  bytes={len(data):,}")
        print(f"[*] Arch   : {arch}  base={hex(base_addr)}")
    else:
        data, base_addr, arch = load_pe_text_section(args.file)
        if args.base:
            base_addr = int(args.base, 0)
        if args.arch != "x64":  # explicit override
            arch = args.arch
        print(f"[*] Arch   : {arch}  base={hex(base_addr)}")

    disassemble(data, base_addr, arch, args.limit, use_color)


if __name__ == "__main__":
    main()
