from __future__ import annotations
import shutil
import time
from pathlib import Path

from androidaudit.session import ADBSession

def pull_storage(session: ADBSession, package: str, output_base: Path) -> dict[str, Path]:
    """Pull sensitive app storage directories from device."""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    local_dir = output_base / timestamp / package
    local_dir.mkdir(parents=True, exist_ok=True)
    
    paths = [
        f"/data/data/{package}/databases/",
        f"/data/data/{package}/shared_prefs/",
        f"/data/data/{package}/files/",
        f"/data/data/{package}/cache/",
        f"/sdcard/Android/data/{package}/"
    ]
    
    pulled_maps: dict[str, Path] = {}
    
    for p in paths:
        dest = local_dir / Path(p).name
        dest.mkdir(parents=True, exist_ok=True)
        try:
            tmp_remote = f"/data/local/tmp/{Path(p).name}"
            session.shell(f"mkdir -p {tmp_remote} && cp -r {p}* {tmp_remote}/ 2>/dev/null")
            session.shell(f"chmod -R 777 {tmp_remote}")
            session.pull(tmp_remote, dest)
            session.shell(f"rm -rf {tmp_remote}")
            pulled_maps[p] = dest
        except Exception:
            pass
            
    return pulled_maps
