import os
import csv
import subprocess


def parse_size(size_str):
    size_str = size_str.strip().upper()
    if size_str.endswith("K"):
        return int(size_str[:-1]) * 1024
    elif size_str.endswith("M"):
        return int(size_str[:-1]) * 1024 * 1024
    else:
        return int(size_str, 16)


def get_partition_info(partition_file, partition_name):
    with open(partition_file, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if row and row[0] == partition_name:
                partition_offset = int(row[3], 16)
                partition_size = parse_size(row[4])
                return partition_offset, partition_size
    return None, None


def get_serial_port():
    try:
        output = subprocess.check_output(["platformio", "device", "list"], text=True)
        for line in output.splitlines():
            if "USB" in line or "COM" in line and "COM1" not in line:
                if line.startswith("/dev") or "COM" in line:
                    return line.split()[0]
    except subprocess.CalledProcessError as e:
        print("Impossibile trovare la porta seriale:", e)
    return None


def dump_spiffs(esptool_path, port, baud, offset, size, output_file):
    command = [
        esptool_path,
        "-p", port,
        "-b 921600",
        "read_flash",
        f"0x{offset:X}",
        f"0x{size:X}",
        output_file
    ]
    subprocess.run(command, check=True)


def extract_spiffs_with_mkspiffs(dump_file, output_dir, mkspiffs_path, target_file="passwords.txt"):
    if not os.path.exists(dump_file):
        print(f"Errore: il file {dump_file} non esiste.")
        return

    os.makedirs(output_dir, exist_ok=True)
    command = [
        mkspiffs_path.replace("\\", "/"),
        "-u", output_dir.replace("\\", "/"),
        dump_file.replace("\\", "/")
    ]
    subprocess.run(command, check=True)


if __name__ == "__main__":
    partition_file = os.path.join(os.getcwd(), "partition.csv")
    partition_name = "spiffs"
    dump_file = os.path.join(os.getcwd(), "spiffs_dump.bin")
    output_dir = os.path.join(os.getcwd(), "data")
    baud = 115200

    esptool_path = os.path.join(os.getcwd(), "tools", "esptool.exe")
    mkspiffs_path = os.path.join(os.getcwd(), "tools", "mkspiffs.exe")

    port = get_serial_port()
    if not port:
        print("Errore: impossibile trovare la porta seriale.")
        exit(1)

    offset, size = get_partition_info(partition_file, partition_name)
    if offset is None or size is None:
        print(f"Errore: partizione '{partition_name}' non trovata nel file {partition_file}.")
        exit(1)

    dump_spiffs(esptool_path, port, baud, offset, size, dump_file)
    extract_spiffs_with_mkspiffs(dump_file, output_dir, mkspiffs_path, target_file="passwords.txt")

    # os.remove(dump_file)