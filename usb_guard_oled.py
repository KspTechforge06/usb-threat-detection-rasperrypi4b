import os
import re
import time
import shutil
import threading
import subprocess
from pathlib import Path

import pyudev
from gpiozero import LED, Buzzer

from luma.core.interface.serial import i2c
from luma.core.render import canvas
from luma.oled.device import sh1106, ssd1306


# ============================================================
# CONFIG
# ============================================================

GREEN_LED_PIN = 17
RED_LED_PIN = 27
BUZZER_PIN = 22

# Most 1.3 inch OLEDs use SH1106.
# If display is glitched, change to "ssd1306".
OLED_DRIVER = "sh1106"

OLED_I2C_ADDRESS = 0x3C
OLED_WIDTH = 128
OLED_HEIGHT = 64

BUZZ_SECONDS = 0.15
BUZZ_GAP_SECONDS = 0.12

MAX_SCAN_FILES = 8000
MAX_SCAN_SECONDS = 25

AUTO_MOUNT_ROOT = "/mnt/usbguard"

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".scr",
    ".pif",
    ".com",
    ".msi",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".ps1",
    ".dll",
    ".lnk",
    ".jar",
}


# ============================================================
# GLOBAL STATE
# ============================================================

context = pyudev.Context()

green_led = LED(GREEN_LED_PIN)
red_led = LED(RED_LED_PIN)
buzzer = Buzzer(BUZZER_PIN)

active_usb_devices = {}
active_threats = {}

screen_lock = threading.Lock()
state_lock = threading.Lock()

oled = None


# ============================================================
# OLED SAFE WRITER
# ============================================================

def setup_oled():
    serial = i2c(port=1, address=OLED_I2C_ADDRESS)

    if OLED_DRIVER.lower() == "ssd1306":
        return ssd1306(serial, width=OLED_WIDTH, height=OLED_HEIGHT)

    return sh1106(serial, width=OLED_WIDTH, height=OLED_HEIGHT)


def draw_oled(title, line1="", line2="", line3="", line4=""):
    """
    Safe OLED writer.
    If the OLED/I2C fails, USB detection should not crash.
    LEDs and buzzer continue working.
    """
    global oled

    lines = [
        str(title)[:21],
        str(line1)[:21],
        str(line2)[:21],
        str(line3)[:21],
        str(line4)[:21],
    ]

    with screen_lock:
        for attempt in range(3):
            try:
                if oled is None:
                    oled = setup_oled()
                    time.sleep(0.15)

                with canvas(oled) as draw:
                    draw.text((0, 0), lines[0], fill=255)
                    draw.text((0, 14), lines[1], fill=255)
                    draw.text((0, 28), lines[2], fill=255)
                    draw.text((0, 42), lines[3], fill=255)
                    draw.text((0, 56), lines[4], fill=255)

                return True

            except OSError as error:
                print(f"[OLED I2C ERROR] {error} | retry {attempt + 1}/3")
                oled = None
                time.sleep(0.25)

            except Exception as error:
                print(f"[OLED ERROR] {error} | retry {attempt + 1}/3")
                oled = None
                time.sleep(0.25)

    print("[OLED SKIPPED] Continuing without display update")
    return False


# ============================================================
# LED + BUZZER
# ============================================================

def all_lights_off():
    red_led.off()
    green_led.off()


def buzz_three_times():
    for _ in range(3):
        buzzer.on()
        time.sleep(BUZZ_SECONDS)
        buzzer.off()
        time.sleep(BUZZ_GAP_SECONDS)


def update_led_state():
    """
    No USB      -> both LEDs OFF
    Safe device -> green ON
    Threat      -> red ON
    """
    with state_lock:
        has_threat = bool(active_threats)
        has_device = bool(active_usb_devices)

    if has_threat:
        green_led.off()
        red_led.on()
    elif has_device:
        red_led.off()
        green_led.on()
    else:
        all_lights_off()


def show_idle_screen():
    update_led_state()

    draw_oled(
        "NO USB DEVICE",
        "No lights active",
        "Insert USB...",
        "Green = Safe",
        "Red = Risk"
    )


def show_safe_screen(device_type, name):
    update_led_state()

    draw_oled(
        "DEVICE SAFE",
        f"Type: {device_type}",
        name,
        "No risky file",
        "Green ON"
    )


def show_scanning_screen(name):
    update_led_state()

    draw_oled(
        "USB STORAGE",
        name,
        "Scanning files...",
        ".exe .bat .ps1",
        "Wait..."
    )


def show_threat_screen():
    update_led_state()

    with state_lock:
        threat = next(iter(active_threats.values()), None)
        device = next(iter(active_usb_devices.values()), None)

    if threat:
        draw_oled(
            "SUSPICIOUS USB",
            f"Type: {threat['type']}",
            threat["name"],
            f"File: {threat['file'][:16]}",
            "RED LOCKED ON"
        )
        return

    if device:
        show_safe_screen(device["type"], device["name"])
    else:
        show_idle_screen()


def trigger_red_alert():
    update_led_state()
    threading.Thread(target=buzz_three_times, daemon=True).start()


# ============================================================
# USB BASIC HELPERS
# ============================================================

def clean(value):
    if value is None:
        return "unknown"

    if isinstance(value, bytes):
        return value.decode(errors="ignore")

    return str(value)


def get_attr(device, key):
    try:
        return clean(device.attributes.asstring(key))
    except Exception:
        try:
            return clean(device.attributes.get(key))
        except Exception:
            return "unknown"


def get_usb_name(device):
    manufacturer = get_attr(device, "manufacturer")
    product = get_attr(device, "product")

    if manufacturer != "unknown" and product != "unknown":
        return f"{manufacturer} {product}"

    if product != "unknown":
        return product

    vendor = device.properties.get("ID_VENDOR")
    model = device.properties.get("ID_MODEL")

    if vendor and model:
        return f"{vendor} {model}"

    if model:
        return model

    return "Unknown USB Device"


def get_vid_pid(device):
    vid = get_attr(device, "idVendor")
    pid = get_attr(device, "idProduct")

    if vid == "unknown":
        vid = device.properties.get("ID_VENDOR_ID", "????")

    if pid == "unknown":
        pid = device.properties.get("ID_MODEL_ID", "????")

    return vid.lower(), pid.lower()


def get_device_key(device):
    """
    sys_name is important because remove events can lose VID/PID.
    Example:
    add    -> sys=1-1.1, VID=03f0, PID=1985
    remove -> sys=1-1.1, VID=????, PID=????
    """
    return device.sys_name or clean(device.sys_path)


def valid_vid_pid(vid, pid):
    bad_values = {"????", "unknown", ""}
    return vid not in bad_values and pid not in bad_values


# ============================================================
# DISCONNECT CLEANUP
# ============================================================

def current_usb_sys_names():
    names = set()

    for dev in context.list_devices(subsystem="usb"):
        if dev.device_type != "usb_device":
            continue

        vid, pid = get_vid_pid(dev)

        # Ignore Linux/Raspberry Pi root hubs.
        if vid == "1d6b":
            continue

        if valid_vid_pid(vid, pid):
            names.add(dev.sys_name)

    return names


def cleanup_disconnected_devices():
    """
    Prevents red LED getting stuck.
    After remove event, rebuild live USB list.
    Any stored device whose sys_name is gone is removed.
    """
    live_names = current_usb_sys_names()

    with state_lock:
        for key, item in list(active_usb_devices.items()):
            if item.get("sys_name") not in live_names:
                active_usb_devices.pop(key, None)

        for key, item in list(active_threats.items()):
            if item.get("sys_name") not in live_names:
                active_threats.pop(key, None)


# ============================================================
# USB TYPE DETECTION
# ============================================================

def detect_input_type_by_vid_pid(vid, pid):
    detected = set()

    for input_device in context.list_devices(subsystem="input"):
        props = input_device.properties

        if props.get("ID_VENDOR_ID", "").lower() != vid:
            continue

        if props.get("ID_MODEL_ID", "").lower() != pid:
            continue

        if props.get("ID_INPUT_KEYBOARD") == "1":
            detected.add("Keyboard")

        if props.get("ID_INPUT_MOUSE") == "1":
            detected.add("Mouse")

        if props.get("ID_INPUT_TOUCHPAD") == "1":
            detected.add("Touchpad")

        if props.get("ID_INPUT_TABLET") == "1":
            detected.add("Tablet")

        if props.get("ID_INPUT_JOYSTICK") == "1":
            detected.add("Joystick")

    if detected:
        return " + ".join(sorted(detected))

    return None


def block_parent_matches(block_device, usb_sys_name, vid, pid):
    parent = block_device.find_parent("usb", "usb_device")

    if parent is None:
        return False

    if parent.sys_name == usb_sys_name:
        return True

    parent_vid, parent_pid = get_vid_pid(parent)

    return parent_vid == vid and parent_pid == pid


def get_usb_block_devices(usb_sys_name, vid, pid):
    block_devices = []

    for block_device in context.list_devices(subsystem="block"):
        devname = block_device.properties.get("DEVNAME")
        devtype = block_device.properties.get("DEVTYPE")

        if not devname:
            continue

        if block_parent_matches(block_device, usb_sys_name, vid, pid):
            block_devices.append({
                "devname": devname,
                "devtype": devtype or "unknown",
            })

    return block_devices


def has_usb_storage_block_device(usb_sys_name, vid, pid):
    return len(get_usb_block_devices(usb_sys_name, vid, pid)) > 0


def detect_type_from_interfaces(device):
    interfaces = device.properties.get("ID_USB_INTERFACES", "").lower()

    if "030101" in interfaces:
        return "Keyboard"

    if "030102" in interfaces:
        return "Mouse"

    if "080650" in interfaces or "0806" in interfaces:
        return "USB Storage"

    if "0e" in interfaces:
        return "Camera"

    if "e00101" in interfaces or "e0" in interfaces:
        return "Bluetooth/Wireless"

    if "0202" in interfaces or "0a" in interfaces:
        return "Phone/Network USB"

    if "0300" in interfaces:
        return "HID Device"

    return None


def detect_type_from_class(device):
    usb_class = get_attr(device, "bDeviceClass").lower()

    class_map = {
        "03": "HID Device",
        "08": "USB Storage",
        "09": "USB Hub",
        "0e": "Camera",
        "e0": "Bluetooth/Wireless",
        "02": "Phone/Network USB",
        "ef": "Multi-function USB",
        "00": "Composite USB",
    }

    return class_map.get(usb_class, "Other USB Device")


def detect_usb_type(device, usb_sys_name, vid, pid):
    # Give Linux time to create input/block devices.
    time.sleep(1.2)

    input_type = detect_input_type_by_vid_pid(vid, pid)

    if input_type:
        return input_type

    if has_usb_storage_block_device(usb_sys_name, vid, pid):
        return "USB Storage"

    interface_type = detect_type_from_interfaces(device)

    if interface_type:
        return interface_type

    return detect_type_from_class(device)


def is_storage_like(device_type, usb_sys_name, vid, pid):
    if has_usb_storage_block_device(usb_sys_name, vid, pid):
        return True

    lowered = device_type.lower()

    storage_words = [
        "storage",
        "composite",
        "multi-function",
        "other usb",
    ]

    return any(word in lowered for word in storage_words)


# ============================================================
# MOUNT + SCAN
# ============================================================

def decode_mount_path(path):
    return path.replace("\\040", " ")


def command_exists(command):
    return shutil.which(command) is not None


def get_mount_from_findmnt(devname):
    try:
        result = subprocess.run(
            ["findmnt", "-nr", "-S", devname, "-o", "TARGET"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )

        for line in result.stdout.splitlines():
            mount_point = line.strip()

            if mount_point and os.path.isdir(mount_point):
                return mount_point

    except Exception as error:
        print(f"[FINDMNT ERROR] {error}")

    return None


def get_mount_from_proc_mounts(devname):
    try:
        real_dev = os.path.realpath(devname)

        with open("/proc/mounts", "r", encoding="utf-8") as mounts:
            for line in mounts:
                parts = line.split()

                if len(parts) < 2:
                    continue

                source = parts[0]
                target = decode_mount_path(parts[1])

                try:
                    same_device = os.path.realpath(source) == real_dev
                except Exception:
                    same_device = source == devname

                if same_device and os.path.isdir(target):
                    return target

    except Exception as error:
        print(f"[PROC MOUNTS ERROR] {error}")

    return None


def parse_udisks_mount_output(output):
    """
    Handles:
    Device /dev/sda1 is already mounted at `/media/ksp/HP USB20FD'.
    Mounted /dev/sda1 at /media/ksp/HP USB20FD.
    """
    patterns = [
        r"mounted at `([^']+)'",
        r"Mounted .* at (/.+?)\.",
        r"at (/.+?)\.",
    ]

    for pattern in patterns:
        match = re.search(pattern, output)

        if match:
            mount_point = match.group(1).strip()

            if os.path.isdir(mount_point):
                return mount_point

    return None


def try_udisks_mount(devname):
    if not command_exists("udisksctl"):
        return None

    try:
        result = subprocess.run(
            ["udisksctl", "mount", "-b", devname],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        output = result.stdout + result.stderr
        print(f"[UDISKSCTL] {output.strip()}")

        parsed_mount = parse_udisks_mount_output(output)

        if parsed_mount:
            return parsed_mount

        return get_mount_from_findmnt(devname) or get_mount_from_proc_mounts(devname)

    except Exception as error:
        print(f"[UDISKS MOUNT ERROR] {error}")

    return None


def try_root_mount_readonly(devname):
    """
    Only works if script is run with sudo/root.
    """
    if os.geteuid() != 0:
        return None

    safe_name = Path(devname).name
    target = os.path.join(AUTO_MOUNT_ROOT, safe_name)

    try:
        os.makedirs(target, exist_ok=True)

        result = subprocess.run(
            ["mount", "-o", "ro,nosuid,nodev,noexec", devname, target],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode == 0:
            print(f"[ROOT MOUNTED] {devname} -> {target}")
            return target

        print(f"[ROOT MOUNT FAILED] {result.stderr.strip()}")

    except Exception as error:
        print(f"[ROOT MOUNT ERROR] {error}")

    return None


def get_mount_points_for_usb(usb_sys_name, vid, pid):
    mount_points = []

    for _ in range(14):
        block_devices = get_usb_block_devices(usb_sys_name, vid, pid)

        if block_devices:
            break

        time.sleep(0.5)

    block_devices = get_usb_block_devices(usb_sys_name, vid, pid)

    print(f"[BLOCK DEVICES] {block_devices}")

    partitions = [d["devname"] for d in block_devices if d["devtype"] == "partition"]
    disks = [d["devname"] for d in block_devices if d["devtype"] == "disk"]

    scan_devices = partitions if partitions else disks

    for devname in scan_devices:
        mount_point = (
            get_mount_from_findmnt(devname)
            or get_mount_from_proc_mounts(devname)
            or try_udisks_mount(devname)
            or try_root_mount_readonly(devname)
        )

        if mount_point and os.path.isdir(mount_point):
            mount_points.append(mount_point)

    return sorted(set(mount_points))


def scan_path_for_suspicious_files(path):
    start_time = time.time()
    scanned_files = 0

    print(f"[SCANNING PATH] {path}")

    try:
        for root, dirs, files in os.walk(path):
            if time.time() - start_time > MAX_SCAN_SECONDS:
                print("[SCAN STOPPED] Time limit reached")
                return None

            for filename in files:
                scanned_files += 1

                if scanned_files > MAX_SCAN_FILES:
                    print("[SCAN STOPPED] File limit reached")
                    return None

                extension = Path(filename).suffix.lower()

                print(f"[FILE] {filename}")

                if extension in SUSPICIOUS_EXTENSIONS:
                    full_path = os.path.join(root, filename)
                    print(f"[SUSPICIOUS FILE FOUND] {full_path}")
                    return filename

    except PermissionError:
        print(f"[PERMISSION DENIED] {path}")
        return "UNSCANNABLE_PERMISSION"

    except Exception as error:
        print(f"[SCAN ERROR] {error}")
        return "UNSCANNABLE_ERROR"

    return None


def scan_usb_for_suspicious_files(usb_sys_name, vid, pid):
    mount_points = get_mount_points_for_usb(usb_sys_name, vid, pid)

    print(f"[MOUNT POINTS] {mount_points}")

    if not mount_points:
        print("[NO MOUNT POINT] Cannot scan USB storage")
        return "UNSCANNABLE_USB"

    for mount_point in mount_points:
        suspicious_file = scan_path_for_suspicious_files(mount_point)

        if suspicious_file:
            return suspicious_file

    return None


# ============================================================
# USB EVENT HANDLERS
# ============================================================

def handle_usb_add(device):
    usb_sys_name = get_device_key(device)
    vid, pid = get_vid_pid(device)
    name = get_usb_name(device)

    # Ignore Raspberry Pi/Linux root hubs.
    if vid == "1d6b":
        return

    print(f"[USB INSERTED] {name} | {vid}:{pid} | sys={usb_sys_name}")

    draw_oled(
        "USB INSERTED",
        "Detecting type...",
        name,
        f"{vid}:{pid}",
        "Please wait"
    )

    device_type = detect_usb_type(device, usb_sys_name, vid, pid)

    with state_lock:
        active_usb_devices[usb_sys_name] = {
            "name": name,
            "type": device_type,
            "vid": vid,
            "pid": pid,
            "sys_name": usb_sys_name,
        }

    update_led_state()

    print(f"[USB TYPE] {device_type}")

    if is_storage_like(device_type, usb_sys_name, vid, pid):
        show_scanning_screen(name)

        suspicious_file = scan_usb_for_suspicious_files(usb_sys_name, vid, pid)

        if suspicious_file:
            with state_lock:
                active_threats[usb_sys_name] = {
                    "name": name,
                    "type": device_type,
                    "file": suspicious_file,
                    "vid": vid,
                    "pid": pid,
                    "sys_name": usb_sys_name,
                }

            print(f"[RED ALERT] {name} | Reason: {suspicious_file}")

            trigger_red_alert()
            show_threat_screen()
            return

    print(f"[SAFE DEVICE] {device_type} | {name}")
    show_safe_screen(device_type, name)


def handle_usb_remove(device):
    usb_sys_name = get_device_key(device)
    vid, pid = get_vid_pid(device)
    name = get_usb_name(device)

    print(f"[USB REMOVED] {name} | {vid}:{pid} | sys={usb_sys_name}")

    with state_lock:
        active_usb_devices.pop(usb_sys_name, None)
        active_threats.pop(usb_sys_name, None)

    # Let Linux update /sys, then remove stale records.
    time.sleep(0.6)
    cleanup_disconnected_devices()
    update_led_state()

    with state_lock:
        has_threat = bool(active_threats)
        remaining_device = next(iter(active_usb_devices.values()), None)

    if has_threat:
        show_threat_screen()
    elif remaining_device:
        show_safe_screen(remaining_device["type"], remaining_device["name"])
    else:
        show_idle_screen()


# ============================================================
# MAIN
# ============================================================

def start_usb_monitor():
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="usb")

    print("USB Guard started.")
    print("No USB = no lights")
    print("Keyboard/mouse/safe USB = green")
    print("Suspicious USB = red + 3 buzzer beeps")

    show_idle_screen()

    for device in iter(monitor.poll, None):
        try:
            if device.device_type != "usb_device":
                continue

            if device.action == "add":
                threading.Thread(
                    target=handle_usb_add,
                    args=(device,),
                    daemon=True,
                ).start()

            elif device.action == "remove":
                handle_usb_remove(device)

        except Exception as error:
            print(f"[ERROR] {error}")
            draw_oled(
                "ERROR",
                "Monitor issue",
                str(error)[:20],
                "Check terminal",
                ""
            )
            update_led_state()


if __name__ == "__main__":
    try:
        start_usb_monitor()

    except KeyboardInterrupt:
        print("Stopping USB Guard...")
        red_led.off()
        green_led.off()
        buzzer.off()

        draw_oled(
            "USB GUARD OFF",
            "Stopped safely",
            "",
            "",
            ""
        )
