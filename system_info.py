"""
system_info.py
--------------
Prints a summary of the current system's hardware and OS information.

Uses only the Python standard library (platform, os, shutil).
For richer data (per-CPU speed, per-disk I/O, etc.) install psutil
and the script will use it automatically when available.

Usage:
    python system_info.py [--json]

Options:
    --json    Output the information as formatted JSON instead of plain text.
"""

import argparse
import json
import os
import platform
import shutil


def _bytes_to_human(num: int) -> str:
    """Convert a byte count to a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} PB"


def gather_info() -> dict:
    info: dict = {}

    # --- Operating system ---
    info["os"] = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor() or "N/A",
        "hostname": platform.node(),
        "python_version": platform.python_version(),
    }

    # --- CPU ---
    cpu: dict = {"architecture": platform.architecture()[0]}
    cpu_count_logical = os.cpu_count()
    cpu["logical_cores"] = cpu_count_logical if cpu_count_logical else "N/A"

    try:
        import psutil  # type: ignore
        cpu["physical_cores"] = psutil.cpu_count(logical=False)
        cpu["usage_percent"] = f"{psutil.cpu_percent(interval=0.5):.1f}%"
        freq = psutil.cpu_freq()
        if freq:
            cpu["current_freq_mhz"] = f"{freq.current:.0f}"
            cpu["max_freq_mhz"] = f"{freq.max:.0f}"
    except ImportError:
        pass

    info["cpu"] = cpu

    # --- Memory (requires psutil) ---
    try:
        import psutil  # type: ignore
        vm = psutil.virtual_memory()
        info["memory"] = {
            "total": _bytes_to_human(vm.total),
            "available": _bytes_to_human(vm.available),
            "used": _bytes_to_human(vm.used),
            "percent_used": f"{vm.percent:.1f}%",
        }
        swap = psutil.swap_memory()
        info["swap"] = {
            "total": _bytes_to_human(swap.total),
            "used": _bytes_to_human(swap.used),
            "percent_used": f"{swap.percent:.1f}%",
        }
    except ImportError:
        info["memory"] = {"note": "Install psutil for memory details"}

    # --- Disk (root / home partition) ---
    check_paths = [os.path.expanduser("~"), "/"]
    seen = set()
    disks = []
    for path in check_paths:
        try:
            usage = shutil.disk_usage(path)
            key = (usage.total, usage.used)
            if key in seen:
                continue
            seen.add(key)
            disks.append({
                "path": path,
                "total": _bytes_to_human(usage.total),
                "used": _bytes_to_human(usage.used),
                "free": _bytes_to_human(usage.free),
                "percent_used": f"{usage.used / usage.total * 100:.1f}%",
            })
        except (FileNotFoundError, PermissionError):
            pass
    info["disk"] = disks

    return info


def print_info(info: dict) -> None:
    section_width = 40

    def header(title):
        print(f"\n{'─' * section_width}")
        print(f"  {title}")
        print('─' * section_width)

    def row(label, value):
        print(f"  {label:<22} {value}")

    header("Operating System")
    os_info = info["os"]
    row("System:", os_info["system"])
    row("Release:", os_info["release"])
    row("Machine:", os_info["machine"])
    row("Processor:", os_info["processor"])
    row("Hostname:", os_info["hostname"])
    row("Python Version:", os_info["python_version"])

    header("CPU")
    cpu = info["cpu"]
    row("Architecture:", cpu["architecture"])
    row("Logical Cores:", str(cpu["logical_cores"]))
    for key in ("physical_cores", "usage_percent", "current_freq_mhz", "max_freq_mhz"):
        if key in cpu:
            label = key.replace("_", " ").title() + ":"
            row(label, str(cpu[key]))

    if "total" in info.get("memory", {}):
        header("Memory")
        mem = info["memory"]
        row("Total:", mem["total"])
        row("Used:", mem["used"])
        row("Available:", mem["available"])
        row("Percent Used:", mem["percent_used"])
    else:
        header("Memory")
        print(f"  {info['memory'].get('note', '')}")

    if "total" in info.get("swap", {}):
        header("Swap")
        sw = info["swap"]
        row("Total:", sw["total"])
        row("Used:", sw["used"])
        row("Percent Used:", sw["percent_used"])

    header("Disk")
    for disk in info["disk"]:
        print(f"  Path: {disk['path']}")
        row("  Total:", disk["total"])
        row("  Used:", disk["used"])
        row("  Free:", disk["free"])
        row("  Percent Used:", disk["percent_used"])
        print()

    print('─' * section_width)


def main():
    parser = argparse.ArgumentParser(description="Display system information.")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    info = gather_info()

    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print_info(info)


if __name__ == "__main__":
    main()
