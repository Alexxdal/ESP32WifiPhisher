import os
import sys
import shutil
import subprocess

# Define the PlatformIO build environment (change if needed)
BUILD_ENV = "esp32-s3-n16r8"  # Adjust based on your PlatformIO environment
BUILD_DIR = os.path.join(".pio", "build", BUILD_ENV)

# Path to esptool.exe (modify if stored in a different location)
ESPTOOL_PATH = os.path.join(os.getcwd(), "tools/esptool.exe")

# Output merged binary path
MERGED_BIN = os.path.join(BUILD_DIR, "release.bin")

# Locate required binary files
bootloader_bin = os.path.join(BUILD_DIR, "bootloader.bin")
partition_table_bin = os.path.join(BUILD_DIR, "partitions.bin")

# Automatically find the firmware binary
application_bin = None
for file in os.listdir(BUILD_DIR):
    if file.endswith(".bin") and "bootloader" not in file and "partitions" not in file:
        application_bin = os.path.join(BUILD_DIR, file)
        break

# Verify that all required binaries exist
if not all(os.path.exists(f) for f in [bootloader_bin, partition_table_bin, application_bin]):
    print("❌ Error: One or more binary files are missing! Ensure the build is completed.")
    sys.exit(1)

# Flash memory addresses (check your sdkconfig if using custom values)
bootloader_addr = 0x0
partition_table_addr = 0x8000
application_addr = 0x10000

try:
    print("\n🔄 Merging binaries into release.bin using esptool.exe...\n")

    # Build the merge command
    merge_command = [
        ESPTOOL_PATH, "--chip", "esp32s3", "merge_bin",
        "-o", MERGED_BIN,
        hex(bootloader_addr), bootloader_bin,
        hex(partition_table_addr), partition_table_bin,
        hex(application_addr), application_bin
    ]

    # Execute esptool.exe with the merge command
    subprocess.run(merge_command, check=True)

    print("✅ Merge completed successfully!")

    # Copy merged firmware to project root for easy access
    shutil.copy(MERGED_BIN, "release.bin")
    print("📂 Merged firmware copied to the project root.")

    print("\n✅ Done! You can now flash it using:")
    print(f"   {ESPTOOL_PATH} --chip esp32s3 write_flash 0x1000 release.bin")

except subprocess.CalledProcessError as e:
    print(f"❌ Error merging binaries: {e}")
    sys.exit(1)