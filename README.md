# tghfghgfhjjh

## Reverse Engineering Scripts

Two Python utilities for static binary analysis and reverse engineering.

---

### 1. `pe_analyzer.py` — Windows PE File Analyzer

Parses a Windows Portable Executable (PE / DLL / EXE) and extracts:

| Feature | Details |
|---------|---------|
| Headers | DOS header, NT file header, Optional header |
| Sections | Name, virtual/raw addresses & sizes, characteristics |
| Imports | DLL names with every imported function and its resolved address |
| Exports | Exported symbol names, ordinals, and RVAs |
| Strings | All embedded printable ASCII strings (optional, configurable min length) |

**Install dependency:**
```bash
pip install pefile
```

**Usage:**
```bash
# Basic analysis (headers + sections + imports + exports)
python pe_analyzer.py notepad.exe

# Include embedded strings, minimum length 6
python pe_analyzer.py malware_sample.dll --strings --min-len 6
```

---

### 2. `disasm_dump.py` — Binary Disassembler

Disassembles binary files (PE executables, raw shellcode, firmware blobs) using
the [Capstone](https://www.capstone-engine.org/) engine and prints annotated
assembly output with colour-coded key instructions (calls, jumps, syscalls, rets).

| Feature | Details |
|---------|---------|
| Auto-detect arch | Reads PE machine type to pick x86 vs x64 automatically |
| PE mode | Disassembles the first executable (`.text`) section |
| Raw mode | Disassembles arbitrary binary data at a given offset/length |
| Architectures | x86, x64, ARM, ARM64, MIPS |
| Highlighting | `call` (yellow), jumps (cyan), `ret` (green), `syscall` (bold) |
| Instruction limit | `--limit N` to cap output for large binaries |

**Install dependencies:**
```bash
pip install capstone pefile
```

**Usage:**
```bash
# Disassemble the .text section of a PE
python disasm_dump.py calc.exe

# Disassemble raw shellcode (x64)
python disasm_dump.py shellcode.bin --raw --arch x64

# Disassemble bytes 0x400–0x800 of a firmware image (x86)
python disasm_dump.py firmware.bin --raw --arch x86 --offset 0x400 --length 0x400

# Show only the first 200 instructions of a PE
python disasm_dump.py malware.exe --limit 200

# Disable colour output (e.g. for piping to a file)
python disasm_dump.py sample.exe --no-color > output.txt
```