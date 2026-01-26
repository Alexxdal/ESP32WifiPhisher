### Features

- **Aircrack**:  
Capture client handshake and check the user input password (WPA/WPA2/WPA3).

- **Evil Twin Attack**:  
Creates a rogue access point (AP) mimicking the target network, thus tricking clients into connecting to it.

- **Karma Attack**:  
Automatically detects devices probing for known networks and sends spoofed responses to trick them into connecting to the rogue AP.

- **Deauther & Advanced Attacks**:  
Disconnects targets using standard deauthentication frames or advanced techniques for Wi-Fi 6 (e.g., negative TX power, EAPOL manipulation, and invalid PMKID injection).

## Flash the firmware
Use the [Online Flasher](https://espwifiphisher.alexxdal.com/) to flash your device.

# WifiPhisher for ESP32

[![GitHub](https://img.shields.io/badge/GitHub-Repository-blue)](https://github.com/Alexxdal/WifiPhisher)

WifiPhisher for ESP32 is a custom implementation of a phishing tool designed for the ESP32 microcontroller. It performs Evil Twin attacks, allowing users to test the security of Wi-Fi networks and execute social engineering phishing scenarios. The project is built using **PlatformIO** and the **ESP-IDF framework**.

## Requirements

### Software

- **PlatformIO**:  
  Integrated into your IDE (e.g., Visual Studio Code). [Install PlatformIO](https://platformio.org/install).

- **ESP-IDF Framework**:  
  Required for building and flashing the firmware. PlatformIO automatically configures this as part of the development environment.

---

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Alexxdal/WifiPhisher.git
cd WifiPhisher
```

### 2. Build and Upload

Open the project with Visual Studio Code and ensure that PlatformIO is correctly set up.

1. Select your target device (e.g. esp32s3 )
2. Connect your ESP32 board to your computer via USB.
3. Click "Upload"

### 3. Monitor Logs

To debug or monitor the ESP32's output logs:
1. Use PlatformIO serial monitor:
  ```bash
   pio device monitor
   ```
2. To stop the monitor, press `Ctrl+C`.

---

## Usage

#### 1. Access Web Interface
1. Connect to the ESP32 rogue AP (default: "MagicWifi" password: "MagicWifi1234" ).
2. Open a browser and go to `http://192.168.4.1/admin.html`.

#### 2. Configure the Attack
1. Select the target Wi-Fi network to impersonate.
2. Choose a phishing scenario (e.g., fake login page).

#### 3. Run the Attack
Once configured, the ESP32 will execute the Evil Twin attack and serve the phishing page.

---

## Screenshots

Here are some visual examples of the tool in action:

### 1. Dashboard
![Settings Page](./screenshots/dashboard_page.png)

### 2. Scan & Sniff
![Settings Page](./screenshots/scan_page.png)

### 3. EvilTwin Page
![EvilTwin Page](./screenshots/elivtwin_page_new.png)

### 4. Karma Attack Page
![EvilTwin Page](./screenshots/karmaattack_page.png)

### 5. Example Phishing Page
![Phishing Page Example](./screenshots/phishing_page_example.png)

---

## Contributions

Contributions are welcome! You can improve phishing scenarios, optimize performance, or add new features.

---

## Disclaimer

This tool is intended strictly for educational purposes and ethical hacking in controlled environments. Unauthorized use of WifiPhisher for malicious purposes is illegal and punishable by law. Always ensure you have explicit permission before conducting any testing.
