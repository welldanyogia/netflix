# Widevine L3 CDM Extraction Guide

## Overview

Widevine CDM (Content Decryption Module) terdiri dari 2 file:
- `device_client_id_blob` - Device identifier
- `device_private_key` - RSA private key untuk decrypt license

## Method 1: Android Emulator (Paling Mudah)

### Setup
```bash
# Install Android Studio dengan emulator
# Buat emulator dengan:
# - API Level 28-30 (Android 9-11)
# - x86_64 architecture
# - Google APIs (bukan Play Store image)
```

### Steps
1. Start emulator
2. Install app yang pakai Widevine (Netflix, Prime Video, dll)
3. Play konten apapun (trigger Widevine initialization)
4. Extract files:

```bash
# Connect ke emulator
adb connect localhost:5554

# CDM biasanya di lokasi ini:
adb pull /data/data/com.netflix.mediaclient/files/
adb pull /data/vendor/mediadrm/

# Atau cari dengan:
adb shell find /data -name "*widevine*" 2>/dev/null
adb shell find /data -name "*client_id*" 2>/dev/null
```

### Lokasi Umum CDM
```
/data/vendor/mediadrm/IDM/
/data/mediadrm/
/data/data/<app>/files/.wv/
/data/data/<app>/files/drmkeys/
```

---

## Method 2: Frida Dump (Device Fisik, Tanpa Root)

### Requirements
- Device dengan USB Debugging enabled
- ADB installed
- Frida installed (`pip install frida-tools`)
- App target harus debuggable ATAU device userdebug

### Frida Script: `dump_cdm.js`

```javascript
// dump_cdm.js - Dump Widevine L3 CDM

Java.perform(function() {
    console.log("[*] Widevine CDM Dumper Started");
    
    // Hook MediaDrm constructor
    var MediaDrm = Java.use("android.media.MediaDrm");
    
    MediaDrm.$init.overload('java.util.UUID').implementation = function(uuid) {
        console.log("[+] MediaDrm initialized with UUID: " + uuid.toString());
        var result = this.$init(uuid);
        
        // Dump device info
        try {
            var deviceId = this.getPropertyByteArray("deviceUniqueId");
            console.log("[+] Device ID: " + bytesToHex(deviceId));
            
            // Save to file
            saveToFile("/sdcard/device_id.bin", deviceId);
        } catch(e) {
            console.log("[-] Error getting device ID: " + e);
        }
        
        return result;
    };
    
    // Hook getKeyRequest untuk capture license request
    MediaDrm.getKeyRequest.overload(
        '[B', '[B', 'java.lang.String', 'int', 'java.util.HashMap'
    ).implementation = function(scope, init, mimeType, keyType, optParams) {
        console.log("[+] getKeyRequest called");
        console.log("    PSSH: " + bytesToHex(init));
        
        var result = this.getKeyRequest(scope, init, mimeType, keyType, optParams);
        var requestData = result.getData();
        
        console.log("[+] License Request: " + bytesToHex(requestData));
        saveToFile("/sdcard/license_request.bin", requestData);
        
        return result;
    };
    
    // Hook provideKeyResponse untuk capture license response
    MediaDrm.provideKeyResponse.implementation = function(scope, response) {
        console.log("[+] provideKeyResponse called");
        console.log("[+] License Response: " + bytesToHex(response));
        saveToFile("/sdcard/license_response.bin", response);
        
        return this.provideKeyResponse(scope, response);
    };
});

// Helper functions
function bytesToHex(bytes) {
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
    }
    return hex.join('');
}

function saveToFile(path, data) {
    try {
        var File = Java.use("java.io.File");
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        
        var file = File.$new(path);
        var fos = FileOutputStream.$new(file);
        fos.write(data);
        fos.close();
        
        console.log("[+] Saved to: " + path);
    } catch(e) {
        console.log("[-] Save error: " + e);
    }
}
```

### Usage
```bash
# Start Frida server (jika pakai rooted device)
# Atau gunakan frida-gadget untuk non-root

# Inject ke Netflix
frida -U -f com.netflix.mediaclient -l dump_cdm.js --no-pause

# Atau attach ke running process
frida -U com.netflix.mediaclient -l dump_cdm.js
```

---

## Method 3: Dumper Tools

### pywidevine
```bash
pip install pywidevine

# Setelah punya CDM files, bisa test dengan:
pywidevine license <device_path> <pssh> <license_url>
```

### Struktur CDM Directory
```
device/
├── device_client_id_blob    # Client ID
└── device_private_key       # RSA Private Key (PEM format)
```

---

## Verifikasi CDM

### Check CDM Valid
```python
from pywidevine.device import Device

# Load device
device = Device.load("./device/")

# Check info
print(f"Security Level: {device.security_level}")
print(f"System ID: {device.system_id}")
print(f"Client ID: {device.client_id}")
```

### Test License Request
```python
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH
import requests

# Load CDM
device = Device.load("./device/")
cdm = Cdm.from_device(device)

# Open session
session_id = cdm.open()

# Generate license request
pssh = PSSH("AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ...")  # Your PSSH
challenge = cdm.get_license_challenge(session_id, pssh)

# Send to license server
response = requests.post(
    "https://license.server.com/license",
    data=challenge,
    headers={"Content-Type": "application/octet-stream"}
)

# Parse license
cdm.parse_license(session_id, response.content)

# Get decryption keys
for key in cdm.get_keys(session_id):
    print(f"Key ID: {key.kid.hex}")
    print(f"Key: {key.key.hex()}")

cdm.close(session_id)
```

---

## Netflix-Specific Challenges

Netflix TIDAK menggunakan standard Widevine license flow:

1. **MSL Encryption** - License request dibungkus MSL
2. **Custom Headers** - Butuh ESN, cookies, dll
3. **Manifest Encrypted** - MPD/manifest juga dienkripsi

### Flow untuk Netflix
```
1. Login → Get cookies (NetflixId, SecureNetflixId)
2. Get ESN → Device identifier
3. MSL Handshake → Key exchange
4. Get Manifest → Encrypted, perlu decrypt
5. License Request → Via MSL, bukan direct
6. Decrypt Content → Pakai keys dari license
```

---

## Legal Warning

⚠️ **PENTING:**
- Extracting CDM mungkin melanggar DMCA/ToS
- Distribusi CDM adalah ilegal
- CDM bisa di-revoke kapan saja
- Gunakan hanya untuk educational purposes

---

## Next Steps

Setelah punya L3 CDM:
1. [ ] Implement MSL client
2. [ ] Handle Netflix authentication
3. [ ] Parse encrypted manifests
4. [ ] Build license request dengan MSL
5. [ ] Decrypt dan download content
