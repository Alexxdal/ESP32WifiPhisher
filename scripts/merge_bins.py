import subprocess
import os
from pathlib import Path

Import("env")

PROJECT_DIR = Path(env["PROJECT_DIR"])
BUILD_DIR   = Path(env.subst("$BUILD_DIR"))
PIOENV      = env["PIOENV"]

DATA_DIR = PROJECT_DIR / "data"
DIST_DIR = PROJECT_DIR / "dist"
DIST_DIR.mkdir(parents=True, exist_ok=True)

print(f"[merge_bins] loaded for env={PIOENV} build_dir={BUILD_DIR}")

def _parse_size(s: str) -> int:
    s = s.strip()
    if not s:
        return 0
    s_up = s.upper()
    if s_up.startswith("0X"):
        return int(s_up, 16)
    mul = 1
    if s_up.endswith("K"):
        mul = 1024
        s_up = s_up[:-1]
    elif s_up.endswith("M"):
        mul = 1024 * 1024
        s_up = s_up[:-1]
    return int(s_up) * mul

def _align_up(x: int, a: int) -> int:
    return (x + (a - 1)) & ~(a - 1)

def _find_file(root: Path, filename: str) -> Path | None:
    for p in root.rglob(filename):
        return p
    return None

def _compute_spiffs_offset_from_csv(csv_path: Path) -> int:
    cur = 0
    spiffs_ofs = None

    lines = csv_path.read_text(encoding="utf-8").splitlines()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        cols = [c.strip() for c in line.split(",")]
        if len(cols) < 5:
            continue

        name = cols[0]
        offset_s = cols[3]
        size_s   = cols[4]

        size = _parse_size(size_s)

        if offset_s:
            cur = _parse_size(offset_s)
        else:
            cur = _align_up(cur, 0x1000)

        if name.lower() == "spiffs":
            spiffs_ofs = cur

        cur += size

    if spiffs_ofs is None:
        raise RuntimeError(f"Non trovo la partizione 'spiffs' in {csv_path}")
    return spiffs_ofs

def _spiffs_bin_path() -> Path:
    return BUILD_DIR / "spiffs.bin"

def _firmware_bin_path() -> Path:
    p = BUILD_DIR / "firmware.bin"
    if p.exists():
        return p
    p2 = _find_file(BUILD_DIR, "firmware.bin")
    if p2:
        return p2
    raise RuntimeError(f"firmware.bin non trovato in {BUILD_DIR}")

def _need_buildfs() -> bool:
    if not DATA_DIR.exists():
        return False
    out = _spiffs_bin_path()
    if not out.exists():
        return True
    out_mtime = out.stat().st_mtime
    for p in DATA_DIR.rglob("*"):
        if p.is_file() and p.stat().st_mtime > out_mtime:
            return True
    return False

def _run_buildfs_if_needed():
    if not DATA_DIR.exists():
        print("[auto] cartella /data assente -> skip buildfs")
        return

    if not _need_buildfs():
        print("[auto] SPIFFS già aggiornato -> skip buildfs")
        return

    print(f"[auto] buildfs per env {PIOENV} ...")
    # usa python -m platformio (non dipende dal PATH di 'pio')
    python = env.subst("$PYTHONEXE")
    subprocess.check_call([python, "-m", "platformio", "run", "-e", PIOENV, "-t", "buildfs"])

def _need_merge(out_file: Path, inputs: list[Path]) -> bool:
    if not out_file.exists():
        return True
    out_mtime = out_file.stat().st_mtime
    return any(i.exists() and i.stat().st_mtime > out_mtime for i in inputs)

def _merge_bin():
    bootloader = _find_file(BUILD_DIR, "bootloader.bin")
    partitions = _find_file(BUILD_DIR, "partitions.bin") or _find_file(BUILD_DIR, "partition-table.bin")
    app_bin    = _firmware_bin_path()
    spiffs_bin = _spiffs_bin_path()

    if not bootloader:
        raise RuntimeError(f"bootloader.bin non trovato in {BUILD_DIR}")
    if not partitions:
        raise RuntimeError(f"partitions.bin/partition-table.bin non trovato in {BUILD_DIR}")
    if not spiffs_bin.exists():
        raise RuntimeError(f"spiffs.bin non trovato in {BUILD_DIR} (buildfs non eseguito?)")

    part_csv = PROJECT_DIR / env.GetProjectOption("board_build.partitions", "partition.csv")
    if not part_csv.exists():
        part_csv = PROJECT_DIR / "partition.csv"
    spiffs_ofs = _compute_spiffs_offset_from_csv(part_csv)

    # --- Rilevamento Chip e Offset Bootloader ---
    # Leggiamo il chip prima per decidere l'offset
    chip = env.BoardConfig().get("build.mcu", "esp32").lower()
    
    # ESP32 "Classic" e S2 usano 0x1000. 
    # S3, C3, C6, H2 e successivi usano 0x0.
    if chip in ["esp32", "esp32s2"]:
        bootloader_ofs = "0x1000"
    elif chip in ["esp32c5"]:
        bootloader_ofs = "0x2000"
    else:
        bootloader_ofs = "0x0"
        
    partitions_ofs = "0x8000"
    app_ofs        = "0x10000"
    spiffs_ofs_s   = f"0x{spiffs_ofs:X}"
    # --------------------------------------------

    python  = env.subst("$PYTHONEXE")
    esptool = env.subst("$UPLOADER")

    flash_mode = env.BoardConfig().get("build.flash_mode", "dio")
    # Se vuoi davvero “universale 4MB”, ok SOLO se la tua partition table sta entro 4MB
    flash_size = "4MB"

    f_flash = str(env.BoardConfig().get("build.f_flash", "40000000")).replace("L", "")
    flash_freq = "80m" if f_flash.isdigit() and int(f_flash) >= 80000000 else "40m"

    out_file = DIST_DIR / f"{PIOENV}-merged.bin"

    inputs = [bootloader, partitions, app_bin, spiffs_bin, part_csv]
    if not _need_merge(out_file, inputs):
        print(f"[auto] merged già aggiornato -> skip ({out_file.name})")
        return

    cmd = [
        str(python), str(esptool),
        "--chip", str(chip),
        "merge_bin",
        "--fill-flash-size", "4MB",
        "-o", str(out_file),
        "--flash_mode", str(flash_mode),
        "--flash_freq", str(flash_freq),
        "--flash_size", str(flash_size),
        bootloader_ofs, str(bootloader),
        partitions_ofs, str(partitions),
        app_ofs, str(app_bin),
        spiffs_ofs_s, str(spiffs_bin),
    ]

    print("\n[auto] Merge command:")
    print(" ".join(cmd))
    subprocess.check_call(cmd)
    print(f"[auto] OK -> {out_file}\n")

# target manuale
env.AddCustomTarget(
    name="webflash",
    dependencies=["buildprog", "buildfs"],
    actions=[lambda *a, **k: _merge_bin()],
    title="WebFlash",
    description="Build firmware + SPIFFS and create dist/<env>-merged.bin",
)

def _auto_after_prog_built(source, target, env, **kwargs):
    # Guardia anti-loop: quando richiamiamo buildfs con "python -m platformio",
    # questo hook si riesegue. Con questa variabile lo blocchiamo.
    if os.environ.get("PWEBFLASH_RUNNING") == "1":
        return

    os.environ["PWEBFLASH_RUNNING"] = "1"
    try:
        _run_buildfs_if_needed()
        _merge_bin()
    finally:
        os.environ.pop("PWEBFLASH_RUNNING", None)


env.AddPostAction("$BUILD_DIR/firmware.bin", _auto_after_prog_built)
