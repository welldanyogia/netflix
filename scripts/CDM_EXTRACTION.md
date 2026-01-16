# CDM Extraction Guide

## Method 1: Frida CDM Dumper (Windows)

### Requirements
```powershell
pip install frida frida-tools
```

### Usage
```powershell
# 1. Open Chrome/Edge
# 2. Run dumper
python cdm_dumper.py

# 3. Select browser (1=Chrome, 2=Edge)
# 4. Play Netflix content
# 5. Ctrl+C to save results
```

### Output
```
cdm_dump/
└── extracted_data.json
```

---

## Method 2: Android Emulator (Easier)

### Setup Android Studio Emulator
```bash
# Create emulator with:
# - API 30 (Android 11)
# - x86_64
# - Google APIs (NOT Play Store)
```

### Extract CDM
```bash
# 1. Install Netflix
adb install netflix.apk

# 2. Play any content (triggers CDM init)

# 3. Pull CDM files
adb root
adb pull /data/vendor/mediadrm/IDM/ ./cdm/

# Or search for it
adb shell find /data -name "*wv*" -o -name "*widevine*" 2>/dev/null
```

### Common CDM Locations
```
/data/vendor/mediadrm/IDM/
/data/mediadrm/
/data/data/com.netflix.mediaclient/files/
```

---

## Method 3: KeyDive (Recommended)

KeyDive adalah tool khusus untuk dump Widevine L3 CDM.

### Install
```bash
git clone https://github.com/hyugogirubato/KeyDive
cd KeyDive
pip install -r requirements.txt
```

### Usage (Android)
```bash
# Connect device via ADB
adb devices

# Run KeyDive
python keydive.py -d

# Play DRM content on device
# Keys will be dumped automatically
```

### Output
```
device/
├── client_id.bin      # Device client ID
└── private_key.pem    # RSA private key
```

---

## Method 4: Manual Chrome CDM Location

### Windows
```
C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\WidevineCdm\<version>\_platform_specific\win_x64\widevinecdm.dll
```

### macOS
```
~/Library/Application Support/Google/Chrome/WidevineCdm/<version>/_platform_specific/mac_x64/
```

### Linux
```
~/.config/google-chrome/WidevineCdm/<version>/_platform_specific/linux_x64/
```

**Note:** The DLL itself doesn't contain the keys. Keys are generated per-session and stored in memory.

---

## Verifying CDM Files

### Check with pywidevine
```python
from pywidevine.device import Device

# Load device
device = Device.load("./device/")

print(f"System ID: {device.system_id}")
print(f"Security Level: {device.security_level}")
print(f"Flags: {device.flags}")
```

### Expected Structure
```
device/
├── device_client_id_blob    # Binary file
└── device_private_key       # PEM or DER format
```

---

## Using Extracted CDM

### With pywidevine
```python
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH

# Load CDM
device = Device.load("./device/")
cdm = Cdm.from_device(device)

# Create session
session_id = cdm.open()

# Generate challenge from PSSH
pssh = PSSH("AAAANHB...")  # Your PSSH
challenge = cdm.get_license_challenge(session_id, pssh)

# Send challenge to license server, get response
# license_response = requests.post(license_url, data=challenge)

# Parse license
cdm.parse_license(session_id, license_response)

# Get keys
for key in cdm.get_keys(session_id):
    print(f"KID: {key.kid.hex}")
    print(f"Key: {key.key.hex()}")

cdm.close(session_id)
```

---

## ⚠️ Important Notes

1. **L3 CDM only** - These methods extract software-level CDM (max 720p)
2. **L1 requires hardware exploit** - Not covered here
3. **CDM can be revoked** - Google may blacklist extracted CDMs
4. **Legal risks** - Check local laws before using
5. **Netflix additional layer** - Even with CDM, Netflix uses MSL encryption
