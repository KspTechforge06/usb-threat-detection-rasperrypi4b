# Raspberry Pi USB Guard OLED Monitor

A Raspberry Pi 4B–based USB security monitor that detects newly connected USB devices, classifies them, scans USB storage for suspicious files, and reports status via LEDs, a buzzer, and a 1.3-inch OLED display.

> **Disclaimer:** This is an educational demo project, not a replacement for professional antivirus or endpoint security software.

---

## Table of Contents

1. [Features](#features)
2. [Hardware](#hardware)
3. [Wiring](#wiring)
4. [Software Setup](#software-setup)
5. [Project Structure](#project-structure)
6. [How It Works](#how-it-works)
7. [Running the Project](#running-the-project)
8. [Expected Output](#expected-output)
9. [Auto-Start on Boot](#auto-start-on-boot)
10. [Troubleshooting](#troubleshooting)
11. [Security Limitations & Future Improvements](#security-limitations--future-improvements)

---

## Features

- Real-time USB insert and remove detection via `pyudev`
- Device classification: Keyboard, Mouse, USB Storage, Hub, Camera, Bluetooth/Wireless, Composite
- File scan on USB storage for suspicious extensions
- Green LED → safe device; Red LED → suspicious device
- Buzzer beeps 3 times on suspicious USB detection
- Live status on OLED display
- Graceful OLED error handling (monitoring continues even if display fails)

---

## Hardware

| Component | Qty |
|---|---|
| Raspberry Pi 4B | 1 |
| MicroSD card (32 GB or 64 GB recommended) | 1 |
| 1.3-inch I2C OLED display | 1 |
| Red LED | 1 |
| Green LED | 1 |
| Active buzzer module | 1 |
| 220 Ω resistors (for LEDs) | 2 |
| Jumper wires | As needed |
| Breadboard | 1 |

> If using a bare buzzer instead of a module, add a transistor driver circuit to avoid drawing too much current from the GPIO pin.

---

## Wiring

| Component | GPIO | Physical Pin |
|---|---|---|
| Green LED (+) | GPIO 17 | Pin 11 |
| Red LED (+) | GPIO 27 | Pin 13 |
| Buzzer signal | GPIO 22 | Pin 15 |
| OLED SDA | GPIO 2 | Pin 3 |
| OLED SCL | GPIO 3 | Pin 5 |
| OLED VCC | 3.3 V | Pin 1 |
| OLED GND | GND | Pin 6 |

**LED wiring pattern:**
```
GPIO pin → 220 Ω resistor → LED (+) leg → LED (−) leg → GND
```

---

## Software Setup

Tested on Raspberry Pi OS with Python 3.

### 1. Install system packages

```bash
sudo apt update
sudo apt install -y python3-pip python3-pil i2c-tools python3-lgpio udisks2 util-linux
```

### 2. Create a virtual environment

```bash
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
```

### 3. Install Python packages

```bash
pip install gpiozero pyudev luma.oled
```

### 4. Enable I2C

```bash
sudo raspi-config
# Interface Options → I2C → Enable
```

### 5. Verify OLED is detected

```bash
i2cdetect -y 1
# Most OLED displays appear at address 0x3c
```

---

## Project Structure

```
usb-oled-monitor/
├── usb_guard_oled.py
├── README.md
└── .venv/
```

---

## How It Works

The script listens for Linux USB events using `pyudev`. On each insert event:

1. Reads device metadata — vendor ID, product ID, manufacturer, product name.
2. Classifies the device type (keyboard, mouse, storage, hub, camera, etc.).
3. If USB storage: finds the mount path and scans all files recursively.
4. If a suspicious extension is found: triggers red alert mode (red LED ON, buzzer beeps 3 times, OLED updates).
5. On removal: clears the device state using `sys_name` (since Linux remove events may lose vendor/product IDs).

### Suspicious File Extensions

These extensions are flagged because they can execute code or launch scripts, particularly on Windows:

```
.exe  .bat  .cmd  .scr  .pif  .com  .msi
.vbs  .vbe  .js   .jse  .wsf  .hta
.ps1  .dll  .lnk  .jar
```

### LED / Buzzer / OLED Behavior

| Situation | Green LED | Red LED | Buzzer | OLED |
|---|---|---|---|---|
| No USB connected | OFF | OFF | — | `No USB Device` |
| Keyboard or Mouse | ON | OFF | — | `Device Safe` |
| USB storage — no suspicious files | ON | OFF | — | `Device Safe` |
| USB storage — suspicious file found | OFF | ON | 3 beeps | `Suspicious USB` |
| Suspicious USB removed | OFF | OFF | — | `No USB Device` |
| OLED I2C error | (continues) | (continues) | (continues) | Error in terminal |

---

## Running the Project

Activate the virtual environment, then run the script:

```bash
source .venv/bin/activate
python3 usb_guard_oled.py
```

If the USB drive isn't scanned due to mount permission issues, run with `sudo`:

```bash
sudo /home/ksp/usb-oled-monitor/.venv/bin/python3 usb_guard_oled.py
```

### OLED Driver Selection

Most 1.3-inch OLED displays use the SH1106 controller. The default in the script:

```python
OLED_DRIVER = "sh1106"
```

If text appears glitched, switch to:

```python
OLED_DRIVER = "ssd1306"
```

---

## Expected Output

**Safe device (mouse):**
```
[USB INSERTED] MOSART Semi. Lenovo 130 Wireless Mouse | 17ef:60ff | sys=1-1.3
[USB TYPE] Mouse
[SAFE DEVICE] Mouse | MOSART Semi. Lenovo 130 Wireless Mouse
```

**Suspicious USB storage:**
```
[USB INSERTED] HP USB Flash Drive | 03f0:1985 | sys=1-1.1
[USB TYPE] USB Storage
[MOUNT POINTS] ['/media/ksp/HP USB20FD']
[SCANNING PATH] /media/ksp/HP USB20FD
[FILE] test.exe
[SUSPICIOUS FILE FOUND] /media/ksp/HP USB20FD/Mini Project/test.exe
[RED ALERT] HP USB Flash Drive | Reason: test.exe
```

**Device removal:**
```
[USB REMOVED] Unknown USB Device | ????:???? | sys=1-1.1
```

> `????:????` on removal is normal — Linux may lose vendor/product metadata before the remove event fires. The script uses `sys_name` to correctly clear device state.

---

## Auto-Start on Boot

### Option A — Crontab (simple)

```bash
crontab -e
```

Add:
```
@reboot /home/ksp/usb-oled-monitor/.venv/bin/python3 /home/ksp/usb-oled-monitor/usb_guard_oled.py
```

### Option B — systemd service (recommended)

Create the service file:

```bash
sudo nano /etc/systemd/system/usb-guard-oled.service
```

Paste:
```ini
[Unit]
Description=Raspberry Pi USB Guard OLED Monitor
After=multi-user.target

[Service]
Type=simple
User=ksp
WorkingDirectory=/home/ksp/usb-oled-monitor
ExecStart=/home/ksp/usb-oled-monitor/.venv/bin/python3 /home/ksp/usb-oled-monitor/usb_guard_oled.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable usb-guard-oled.service
sudo systemctl start usb-guard-oled.service
sudo systemctl status usb-guard-oled.service
```

---

## Troubleshooting

### OLED shows glitched text

Change the driver in the script:
```python
OLED_DRIVER = "ssd1306"   # or "sh1106"
```
Also verify wiring: SDA → GPIO 2, SCL → GPIO 3, VCC → 3.3 V (not 5 V), GND → GND.

---

### `OSError: [Errno 5] Input/output error` on OLED

I2C communication failed temporarily. Common causes:
- Loose jumper wires
- Wrong SDA/SCL pins
- OLED connected to 5 V instead of 3.3 V
- Buzzer causing electrical noise on the power rail

The script handles these errors gracefully — USB monitoring continues even if the display fails.

---

### `.exe` file is not detected

Check whether the USB drive is mounted:
```bash
ls /media/ksp/
lsblk
```

If it isn't mounted automatically, run the script with `sudo` (see [Running the Project](#running-the-project)).

---

### GPIOZero warning about NativeFactory

Install the GPIO backend:
```bash
sudo apt install -y python3-lgpio
```

If using a virtual environment, recreate it:
```bash
deactivate
rm -rf .venv
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install gpiozero pyudev luma.oled
```

---

### Red LED stays ON after USB removal

The script uses `sys_name` to clear threat records. If the red LED still stays on:

1. Press `Ctrl + C` to stop the script.
2. Disconnect all USB devices.
3. Restart the script and reinsert devices one at a time.

---

## Security Limitations & Future Improvements

This project checks suspicious file extensions only. A production-grade endpoint security tool would also need:

- File hashing and signature database matching
- YARA rule scanning
- Sandboxed execution and behavioral analysis
- VirusTotal or local malware database integration
- File metadata and entropy analysis

### Planned Improvements

- YARA rule integration
- SHA-256 hash checking against known malware databases
- Scan log storage (SQLite or flat file)
- Web dashboard for remote monitoring
- Telegram / email alert on detection
- Physical reset button
- USB device whitelist
- Quarantine mode
- AI-powered risk explanation on OLED

---

*Made by Priyanshu Chawda — Raspberry Pi USB security monitoring project.*
