"""
Quick script to read ESP32 MAC address from its serial output.
The ESP32 must already be running a sketch that prints the MAC,
OR we read the bootloader ROM log which always prints the MAC at boot.

Usage:  python read_mac.py
"""
import serial
import time

PORT     = "COM9"
BAUDRATE = 115200
TIMEOUT  = 8  # seconds to wait for MAC line

print(f"Connecting to {PORT} at {BAUDRATE} baud...")

try:
    with serial.Serial(PORT, BAUDRATE, timeout=1) as ser:
        ser.setDTR(False)   # pull EN / reset low
        time.sleep(0.2)
        ser.setDTR(True)    # release — triggers ESP32 reboot
        time.sleep(0.1)

        print("ESP32 rebooting — scanning boot log for MAC address...\n")

        start = time.time()
        mac_found = False

        while time.time() - start < TIMEOUT:
            line = ser.readline().decode("utf-8", errors="replace").strip()
            if line:
                print(f"  {line}")
            # ESP-IDF ROM bootloader always logs: "Base MAC address from BLK0 of EFUSE:"
            # or shorter chips just print: "mac: XX:XX:XX:XX:XX:XX"
            lower = line.lower()
            if "mac:" in lower or "efuse" in lower or "base mac" in lower:
                print(f"\n>>> MAC line detected: {line}")
                mac_found = True
            # Also check for ESP8266-style chips
            if "chip mac" in lower or "wifi mac" in lower:
                print(f"\n>>> MAC line detected: {line}")
                mac_found = True

        if not mac_found:
            print("\n[INFO] MAC not found in boot log.")
            print("       If your ESP32 is running a custom sketch, add this to setup():")
            print('       Serial.begin(115200);')
            print('       Serial.print("MAC: ");')
            print('       Serial.println(WiFi.macAddress());')

except serial.SerialException as e:
    print(f"[ERROR] Could not open {PORT}: {e}")
    print("        Make sure the ESP32 is plugged in and no other program (Arduino IDE) is using the port.")
