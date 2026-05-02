Raspberry Pi USB Guard OLED Monitor
A Raspberry Pi 4B based USB monitoring project that detects newly connected USB devices, identifies device type, scans USB storage for suspicious executable/script files, and shows the security status using LEDs, a buzzer, and an OLED display.
This project is designed for a mini-project / security demo where:
No USB device connected → both LEDs OFF
Safe USB device connected → green LED ON
Suspicious USB storage detected → red LED ON + buzzer beeps 3 times
USB details are displayed on a 1.3-inch OLED screen
> Important: This is not a full antivirus engine. It treats risky file extensions such as `.exe`, `.bat`, `.ps1`, `.dll`, etc. as suspicious indicators.
---
Features
Detects USB insert and remove events in real time
Identifies common USB device types:
Keyboard
Mouse
USB storage
USB hub
Camera
Bluetooth / wireless device
Composite USB device
Scans USB storage for suspicious file extensions
Shows live status on OLED display
Uses green LED for safe devices
Uses red LED for suspicious devices
Buzzer beeps 3 times when suspicious USB is detected
Red LED stays ON until the suspicious USB is removed
OLED errors are handled safely so the main USB monitoring does not crash
---
Hardware Required
Component	Quantity
Raspberry Pi 4B	1
MicroSD card, 32 GB or 64 GB recommended	1
1.3-inch I2C OLED display	1
Red LED	1
Green LED	1
Buzzer / active buzzer module	1
220Ω resistors for LEDs	2
Jumper wires	As needed
Breadboard	1
---
GPIO Wiring
Component	Raspberry Pi GPIO	Physical Pin
Green LED positive	GPIO 17	Pin 11
Red LED positive	GPIO 27	Pin 13
Buzzer signal	GPIO 22	Pin 15
OLED SDA	GPIO 2	Pin 3
OLED SCL	GPIO 3	Pin 5
OLED VCC	3.3V	Pin 1
OLED GND	GND	Pin 6
Recommended LED wiring:
```text
GPIO pin -> 220Ω resistor -> LED positive leg
LED negative leg -> GND
```
For buzzer, an active buzzer module is recommended. If using a bare buzzer, use a transistor driver circuit instead of drawing too much current directly from the GPIO pin.
---
Software Requirements
Tested on Raspberry Pi OS with Python 3.
Install required system packages:
```bash
sudo apt update
sudo apt install -y python3-pip python3-pil i2c-tools python3-lgpio udisks2 util-linux
```
Create and activate a virtual environment:
```bash
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
```
Install Python packages:
```bash
pip install gpiozero pyudev luma.oled
```
Enable I2C:
```bash
sudo raspi-config
```
Then go to:
```text
Interface Options -> I2C -> Enable
```
Check if OLED is detected:
```bash
i2cdetect -y 1
```
Most OLED displays show address:
```text
0x3c
```
---
Project Structure
```text
usb-oled-monitor/
├── usb_guard_oled.py
├── README.md
└── .venv/
```
---
How It Works
The script listens to Linux USB events using `pyudev`.
When a USB device is inserted:
The script reads device metadata such as vendor ID, product ID, manufacturer, and product name.
It tries to classify the device as keyboard, mouse, storage, hub, camera, or another USB type.
If the device is USB storage, it finds the mounted path.
It scans files inside the USB drive.
If a suspicious file extension is found, it switches to red alert mode.
---
Detection Logic
Suspicious file extensions include:
```text
.exe
.bat
.cmd
.scr
.pif
.com
.msi
.vbs
.vbe
.js
.jse
.wsf
.hta
.ps1
.dll
.lnk
.jar
```
These files are treated as suspicious because they can execute code or launch scripts on Windows systems.
---
LED and Buzzer Behavior
Situation	Green LED	Red LED	Buzzer	OLED
No USB connected	OFF	OFF	OFF	No USB Device
Keyboard connected	ON	OFF	OFF	Device Safe
Mouse connected	ON	OFF	OFF	Device Safe
USB storage without risky files	ON	OFF	OFF	Device Safe
USB storage with `.exe` / suspicious file	OFF	ON	3 beeps	Suspicious USB
Suspicious USB removed	OFF if no device left	OFF	OFF	No USB Device
OLED I2C error	LED logic continues	LED logic continues	Continues	Error printed in terminal
---
Running the Project
Activate the virtual environment:
```bash
source .venv/bin/activate
```
Run the script:
```bash
python3 usb_guard_oled.py
```
If the USB drive is not scanned properly because of mount permission issues, run:
```bash
sudo /home/ksp/usb-oled-monitor/.venv/bin/python3 usb_guard_oled.py
```
---
Expected Terminal Output
For a safe mouse:
```text
[USB INSERTED] MOSART Semi. Lenovo 130 Wireless Mouse | 17ef:60ff | sys=1-1.3
[USB TYPE] Mouse
[SAFE DEVICE] Mouse | MOSART Semi. Lenovo 130 Wireless Mouse
```
For a USB drive containing an `.exe` file:
```text
[USB INSERTED] HP USB Flash Drive | 03f0:1985 | sys=1-1.1
[USB TYPE] USB Storage
[MOUNT POINTS] ['/media/ksp/HP USB20FD']
[SCANNING PATH] /media/ksp/HP USB20FD
[FILE] test.exe
[SUSPICIOUS FILE FOUND] /media/ksp/HP USB20FD/Mini Project/test.exe
[RED ALERT] HP USB Flash Drive | Reason: test.exe
```
For USB removal:
```text
[USB REMOVED] Unknown USB Device | ????:???? | sys=1-1.1
```
The `????:????` value during removal is normal on Linux because the USB metadata may disappear before the remove event is processed. The script uses `sys_name` to clear the device state correctly.
---
OLED Driver Selection
Most 1.3-inch OLED displays use SH1106.
In the Python file:
```python
OLED_DRIVER = "sh1106"
```
If your display looks glitched, change it to:
```python
OLED_DRIVER = "ssd1306"
```
Then run the script again.
---
Troubleshooting
1. OLED shows glitched text
Try changing:
```python
OLED_DRIVER = "sh1106"
```
to:
```python
OLED_DRIVER = "ssd1306"
```
Also check wiring:
```text
OLED SDA -> GPIO 2
OLED SCL -> GPIO 3
OLED VCC -> 3.3V
OLED GND -> GND
```
---
2. OLED gives `OSError: [Errno 5] Input/output error`
This usually means I2C communication failed temporarily.
Check:
Loose jumper wires
Wrong SDA/SCL pins
Weak power connection
Buzzer causing electrical noise
OLED connected to 5V instead of 3.3V
The latest code handles OLED errors safely, so the USB monitor should continue working even if one display update fails.
---
3. `.exe` file is not detected
Check whether the USB is mounted:
```bash
ls /media/ksp/
```
Also check block devices:
```bash
lsblk
```
Run the script with sudo if required:
```bash
sudo /home/ksp/usb-oled-monitor/.venv/bin/python3 usb_guard_oled.py
```
---
4. GPIOZero warning appears
If you see a warning about GPIOZero falling back to NativeFactory, install the GPIO backend:
```bash
sudo apt install -y python3-lgpio
```
If you are using a virtual environment, recreate it with system packages:
```bash
deactivate
rm -rf .venv
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install gpiozero pyudev luma.oled
```
---
5. Red LED stays ON after USB removal
The fixed code uses the USB `sys_name` to clear stale threat records because Linux remove events can lose vendor/product IDs.
If red still stays ON:
Stop the script with `Ctrl + C`
Disconnect all USB devices
Run the script again
Insert devices one by one
---
Auto Start on Boot
Open crontab:
```bash
crontab -e
```
Add this line:
```bash
@reboot /home/ksp/usb-oled-monitor/.venv/bin/python3 /home/ksp/usb-oled-monitor/usb_guard_oled.py
```
For better reliability, a `systemd` service is recommended.
Example service file:
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
Enable service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable usb-guard-oled.service
sudo systemctl start usb-guard-oled.service
```
Check status:
```bash
sudo systemctl status usb-guard-oled.service
```
---
Security Limitations
This project does not perform deep malware analysis.
It currently checks for suspicious file extensions only. A real antivirus would need:
File hashing
Signature database
YARA rules
Sandboxing
Behavioral analysis
VirusTotal or local malware database integration
File metadata and entropy checks
For a college mini-project, this is a strong hardware + software security demo because it combines:
USB event monitoring
Device classification
File scanning
Hardware alert system
OLED status output
---
Future Improvements
Possible upgrades:
Add YARA rule scanning
Add SHA256 hash checking
Store scan logs in a database
Add web dashboard
Add Telegram/email alert
Add physical reset button
Add whitelist for trusted USB devices
Add quarantine mode
Add camera/OCR display for project demo
Add AI explanation of detected risk
---
Disclaimer
This project is for educational and demonstration purposes. It should not be used as a replacement for professional endpoint security or antivirus software.
---
Author
Made by Priyanshu Chawda as a Raspberry Pi USB security monitoring project.
