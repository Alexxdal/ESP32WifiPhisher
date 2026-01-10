# scripts/buildfs.py
import os
import subprocess
from pathlib import Path

Import("env")

def _data_dir() -> Path:
    # cartella standard di PlatformIO per i file del filesystem
    return Path(env["PROJECT_DIR"]) / "data"

def _spiffs_bin() -> Path:
    return Path(env.subst("$BUILD_DIR")) / "spiffs.bin"

def _need_buildfs() -> bool:
    data = _data_dir()
    if not data.exists():
        # niente data/ -> niente fs
        return False

    out = _spiffs_bin()
    if not out.exists():
        return True

    out_mtime = out.stat().st_mtime
    # se qualunque file in data/ è più nuovo di spiffs.bin, rigenero
    for p in data.rglob("*"):
        if p.is_file() and p.stat().st_mtime > out_mtime:
            return True
    return False

def _run_buildfs(source, target, env_):
    if not _need_buildfs():
        print("[auto_buildfs] SPIFFS già aggiornato, skip.")
        return

    pioenv = env_["PIOENV"]
    print(f"[auto_buildfs] Build SPIFFS (buildfs) per env: {pioenv}")

    # Richiama PlatformIO per eseguire buildfs nello stesso env
    cmd = ["pio", "run", "-e", pioenv, "-t", "buildfs"]
    print("[auto_buildfs] " + " ".join(cmd))
    subprocess.check_call(cmd)

# Aggancio: dopo la build del programma
env.AddPostAction("buildprog", _run_buildfs)