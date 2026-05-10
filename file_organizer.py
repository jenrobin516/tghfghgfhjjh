"""
file_organizer.py
-----------------
Organises files in a directory into sub-folders named after their extensions.

Usage:
    python file_organizer.py <directory> [--dry-run]

Example:
    python file_organizer.py ~/Downloads --dry-run
"""

import argparse
import shutil
from pathlib import Path


EXTENSION_MAP = {
    # Images
    ".jpg": "Images", ".jpeg": "Images", ".png": "Images",
    ".gif": "Images", ".bmp": "Images", ".svg": "Images", ".webp": "Images",
    # Documents
    ".pdf": "Documents", ".doc": "Documents", ".docx": "Documents",
    ".xls": "Documents", ".xlsx": "Documents", ".ppt": "Documents",
    ".pptx": "Documents", ".txt": "Documents", ".md": "Documents",
    # Audio
    ".mp3": "Audio", ".wav": "Audio", ".flac": "Audio", ".aac": "Audio",
    # Video
    ".mp4": "Video", ".mov": "Video", ".avi": "Video", ".mkv": "Video",
    # Code
    ".py": "Code", ".js": "Code", ".ts": "Code", ".html": "Code",
    ".css": "Code", ".java": "Code", ".cpp": "Code", ".c": "Code",
    # Archives
    ".zip": "Archives", ".tar": "Archives", ".gz": "Archives",
    ".rar": "Archives", ".7z": "Archives",
}


def organise(directory: Path, dry_run: bool = False) -> None:
    """Move files in *directory* into extension-based sub-folders."""
    if not directory.is_dir():
        raise NotADirectoryError(f"'{directory}' is not a directory.")

    moved = 0
    for item in sorted(directory.iterdir()):
        if not item.is_file():
            continue

        folder_name = EXTENSION_MAP.get(item.suffix.lower(), "Misc")
        dest_dir = directory / folder_name
        dest = dest_dir / item.name

        if dry_run:
            print(f"[dry-run] Would move: {item.name}  →  {folder_name}/")
        else:
            dest_dir.mkdir(exist_ok=True)
            shutil.move(str(item), dest)
            print(f"Moved: {item.name}  →  {folder_name}/")
        moved += 1

    if moved == 0:
        print("No files to organise.")
    elif not dry_run:
        print(f"\nDone – {moved} file(s) organised.")


def main():
    parser = argparse.ArgumentParser(
        description="Organise files in a directory into sub-folders by extension."
    )
    parser.add_argument("directory", help="Path to the directory to organise")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without moving any files",
    )
    args = parser.parse_args()

    organise(Path(args.directory), dry_run=args.dry_run)


if __name__ == "__main__":
    main()
