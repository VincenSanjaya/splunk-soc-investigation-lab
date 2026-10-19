import csv
import re
from pathlib import Path

DATASETS = Path("datasets")

def convert_process_creation():
    src = DATASETS / "process-creation.txt"
    dst = DATASETS / "process-creation.csv"

    rows = []

    with open(src, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("Time |") or line.startswith("-"):
                continue

            parts = [p.strip() for p in line.split("|")]

            if len(parts) < 7:
                continue

            rows.append({
                "_time": parts[0],
                "EventID": parts[1],
                "Image": parts[2],
                "CommandLine": parts[3],
                "ParentImage": parts[4],
                "ParentCommandLine": parts[5],
                "User": parts[6],
            })

    with open(dst, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "_time",
                "EventID",
                "Image",
                "CommandLine",
                "ParentImage",
                "ParentCommandLine",
                "User",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] {dst} -> {len(rows)} events")


def convert_lsass():
    src = DATASETS / "lsass-process-access.txt"
    dst = DATASETS / "lsass-process-access.csv"

    rows = []

    with open(src, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("Time |") or line.startswith("-"):
                continue

            parts = [p.strip() for p in line.split("|")]

            if len(parts) < 7:
                continue

            rows.append({
                "_time": parts[0],
                "EventID": parts[1],
                "SourceImage": parts[2],
                "TargetImage": parts[3],
                "GrantedAccess": parts[4],
                "CallTrace": parts[5],
                "User": parts[6],
            })

    with open(dst, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "_time",
                "EventID",
                "SourceImage",
                "TargetImage",
                "GrantedAccess",
                "CallTrace",
                "User",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] {dst} -> {len(rows)} events")


def convert_powershell():
    src = DATASETS / "powershell-4104.txt"
    dst = DATASETS / "powershell-4104.csv"

    rows = []

    current_time = None
    current_event = None
    current_script = []

    pattern = re.compile(r"^(.*?) \| (\d+) \| (.*)$")

    with open(src, "r", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")

            if line.startswith("Time |") or line.startswith("-"):
                continue

            match = pattern.match(line)

            if match:
                if current_time is not None:
                    rows.append({
                        "_time": current_time,
                        "EventID": current_event,
                        "ScriptBlockText": "\n".join(current_script),
                    })

                current_time = match.group(1).strip()
                current_event = match.group(2).strip()
                current_script = [match.group(3)]

            elif current_time is not None:
                current_script.append(line)

    if current_time is not None:
        rows.append({
            "_time": current_time,
            "EventID": current_event,
            "ScriptBlockText": "\n".join(current_script),
        })

    with open(dst, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "_time",
                "EventID",
                "ScriptBlockText",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] {dst} -> {len(rows)} events")


if __name__ == "__main__":
    convert_process_creation()
    convert_lsass()
    convert_powershell()