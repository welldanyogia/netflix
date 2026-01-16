# Widevine Chrome Extension Interceptor

## Cara Install

1. Buka Chrome, ketik `chrome://extensions/`
2. Enable "Developer mode" (toggle kanan atas)
3. Klik "Load unpacked"
4. Pilih folder `chrome_extension/`

## Cara Pakai

1. Buka Netflix/streaming site di Chrome
2. Buka DevTools (F12) → Console tab
3. Play video apapun
4. Lihat console untuk captured data:
   - PSSH (initialization data)
   - License Request
   - License Response

5. Ketik `dumpWVData()` di console untuk export semua data

## Output yang Didapat

```javascript
{
  "pssh": [
    {
      "timestamp": 1234567890,
      "type": "cenc",
      "pssh": "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7Q..."
    }
  ],
  "licenseRequests": [
    {
      "timestamp": 1234567890,
      "messageType": "license-request",
      "message": "CAESvAMK..."  // Base64
    }
  ],
  "licenseResponses": [
    {
      "timestamp": 1234567890,
      "response": "CAIS..."  // Base64
    }
  ]
}
```

## Langkah Selanjutnya

Setelah dapat PSSH dan License Response, gunakan `pywidevine` untuk extract keys:

```python
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH
import base64

# Load CDM (harus punya device files)
device = Device.load("./device/")
cdm = Cdm.from_device(device)

# Parse PSSH
pssh = PSSH("AAAAW3Bzc2gAAAAA...")  # dari captured data

# Open session
session_id = cdm.open()
challenge = cdm.get_license_challenge(session_id, pssh)

# Jika sudah punya license response dari intercept:
license_response = base64.b64decode("CAIS...")  # dari captured data
cdm.parse_license(session_id, license_response)

# Get keys
for key in cdm.get_keys(session_id):
    print(f"KID: {key.kid.hex}")
    print(f"KEY: {key.key.hex()}")

cdm.close(session_id)
```

## Catatan untuk Netflix

Netflix menggunakan MSL encryption, jadi license request/response yang di-capture sudah di-wrap dalam MSL. Perlu decrypt MSL dulu sebelum bisa parse Widevine license.

## ⚠️ Disclaimer

Tool ini hanya untuk educational purpose. Jangan gunakan untuk bypass DRM atau download konten ilegal.
