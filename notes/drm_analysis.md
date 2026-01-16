# Netflix DRM Implementation Analysis

## Overview

Netflix menggunakan kombinasi **Widevine DRM** + **MSL (Message Security Layer)** untuk proteksi konten.

## Komponen Utama

### 1. MSL (Message Security Layer)
Protokol keamanan proprietary Netflix untuk komunikasi terenkripsi.

**Lokasi:** `com/netflix/msl/`

| File | Fungsi |
|------|--------|
| `MslException.java` | Base exception |
| `MslCryptoException.java` | Encryption errors |
| `MslKeyExchangeException.java` | Key exchange errors |
| `MslEntityAuthException.java` | Entity authentication |
| `MslMasterTokenException.java` | Master token handling |
| `client/api/WidevineContextException.java` | Widevine-specific errors |

### 2. Widevine Configuration
**Lokasi:** `com/netflix/mediaclient/service/webclient/model/leafs/DeviceConfigData.java`

```java
private final boolean isWidevineL1Enabled;      // Hardware-level DRM (HD/4K)
private final boolean isWidevineL1ReEnabled;    // Re-enable flag
private final boolean isEnabledWidevineL3SystemId4266;  // Software-level DRM
```

**Security Levels:**
- **L1**: Hardware TEE, supports HD/4K/HDR
- **L3**: Software only, max 480p

### 3. License Handler (Obfuscated)
**Lokasi:** `o/C1535aVj.java`

```java
// Content-Type based on DRM type:
// PlayReady: "text/xml"
// Widevine:  "application/octet-stream"
// Other:     "application/json"

// PlayReady SOAP Action:
"http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense"
```

### 4. DRM Status Codes
**Lokasi:** `com/netflix/mediaclient/StatusCode.java`

| Code | Name |
|------|------|
| -90 | DRM_FAILURE_CDM_PROVISIONING |
| -92 | DRM_FAILURE_CDM_PROVISIONING_EMPTY |
| -93 | DRM_FAILURE_CDM_FAILED_TO_PROVIDE_PROVISION_RESPONSE |
| -94 | DRM_RESOURCES_NOT_READY |
| -95 | DRM_RESOURCES_SUSPENDED |
| -96 | DRM_FAILURE_MEDIADRM_RECOVERY_FROM_SUSPEND_UNABLE_TO_CREATE_DRM |
| -97 | DRM_FAILURE_MEDIADRM_SUSPENDED_KEYS_RESTORE_FAILED |
| -98 | DRM_FAILURE_MEDIADRM_IN_RECOVERY_FROM_SUSPEND_KEYS_RESTORE_FAILED |
| -99 | DRM_FAILURE_MEDIADRM_STATE_EXCEPTION |
| -100 | DRM_FAILURE_CDM_GENERIC_ERROR |

### 5. ExoPlayer DRM Integration
**Lokasi:** `androidx/media3/exoplayer/drm/`

- `DefaultDrmSessionManager.java` - Manages DRM sessions
- `DefaultDrmSession.java` - Individual session handling
- `DrmSession.java` - Interface

## DRM Flow

```
1. App Start
   └── Check DeviceConfigData (Widevine L1/L3 support)

2. Content Request
   └── MSL handshake (key exchange, authentication)

3. License Acquisition
   ├── Build license request
   ├── Send to license server via MSL
   └── Receive encrypted keys

4. Playback
   ├── ExoPlayer creates DrmSession
   ├── MediaDrm decrypts content
   └── Render to secure surface (L1) or normal (L3)
```

## Key Files untuk Analysis

| Priority | Path | Description |
|----------|------|-------------|
| HIGH | `o/C1535aVj.java` | License URL handler |
| HIGH | `o/C20187irQ.java` | MSL client usage |
| HIGH | `o/AbstractC18640hzo.java` | MSL network requests |
| MEDIUM | `DeviceConfigData.java` | Widevine config flags |
| MEDIUM | `StatusCode.java` | Error codes reference |

## Challenges

1. **Heavy obfuscation** - Most Netflix code in `o/` package
2. **MSL encryption** - All API calls encrypted
3. **Device binding** - Keys tied to device ESN
4. **Root detection** - Won't run on rooted devices
5. **Widevine L1** - Requires hardware TEE, can't be bypassed in software

## MSL Key Exchange Flow

### Overview
Netflix menggunakan **ALE (Application Level Encryption)** dengan RSA-OAEP-256 untuk key exchange.

### Key Components

#### 1. AleService (`com/netflix/ale/AleService.java`)
Entry point untuk key provisioning.

```java
// Key exchange schemes:
AleKeyxScheme.CLEAR       // No encryption (debug?)
AleKeyxScheme.RSA_OAEP_256 // Production - RSA OAEP with SHA-256
```

#### 2. KeyExchangeRsaOaep (`com/netflix/ale/KeyExchangeRsaOaep.java`)
Handles RSA key exchange.

```java
// Request data structure:
{
  "scheme": "RSA_OAEP_256",
  "pubkey": "<base64_spki_public_key>"
}

// Response processing:
- Receives wrapped key from server
- Unwraps using private key
- Creates JWE session
```

#### 3. MSL Client Interface (`o/InterfaceC18394hvG.java`)
Main MSL client interface (obfuscated).

```java
// Key methods:
e(String userId)     // Check if user known to MSL
f()                  // Get restore data (C28711muQ)
b(String, String)    // Get MSL credentials
d(String)            // Get MSL credentials by user
```

#### 4. MSL Agent (`o/C18406hvS.java`)
Concrete MSL implementation.

```java
// Agent name: "msl"
// Load event: Sessions.MSL_AGENT_LOADED
// Handles: user auth, token management, key storage
```

### Key Exchange Sequence

```
┌─────────┐                    ┌─────────────┐                    ┌─────────┐
│  App    │                    │  AleService │                    │ Netflix │
└────┬────┘                    └──────┬──────┘                    └────┬────┘
     │                                │                                │
     │ 1. Create AleService           │                                │
     │───────────────────────────────>│                                │
     │                                │                                │
     │                    2. Generate RSA keypair                      │
     │                    (AleCrypto.generateRsaOaepKey)               │
     │                                │                                │
     │ 3. getProvisioningRequest()    │                                │
     │───────────────────────────────>│                                │
     │                                │                                │
     │    KeyProvisionRequest {       │                                │
     │      ver: 1,                   │                                │
     │      scheme: AleScheme,        │                                │
     │      type: AleType,            │                                │
     │      keyx: {                   │                                │
     │        scheme: RSA_OAEP_256,   │                                │
     │        pubkey: <base64>        │                                │
     │      }                         │                                │
     │    }                           │                                │
     │<───────────────────────────────│                                │
     │                                │                                │
     │ 4. Send to Netflix server ─────────────────────────────────────>│
     │                                │                                │
     │ 5. Receive KeyProvisionResponse <───────────────────────────────│
     │    {                           │                                │
     │      ver: 1,                   │                                │
     │      scheme: AleScheme,        │                                │
     │      token: <session_token>,   │                                │
     │      ttl: <seconds>,           │                                │
     │      keyx: {                   │                                │
     │        scheme: RSA_OAEP_256,   │                                │
     │        kid: <key_id>,          │                                │
     │        wrappedkey: <encrypted> │                                │
     │      }                         │                                │
     │    }                           │                                │
     │                                │                                │
     │ 6. createSession(response)     │                                │
     │───────────────────────────────>│                                │
     │                                │                                │
     │              7. processKeyxResponse()                           │
     │              - Decrypt wrappedkey with RSA private key          │
     │              - Create JWE session object                        │
     │              - Calculate expiry & renewal times                 │
     │                                │                                │
     │    AleSession {                │                                │
     │      token,                    │                                │
     │      expiry,                   │                                │
     │      renewalTime,              │                                │
     │      jwe (decrypted key)       │                                │
     │    }                           │                                │
     │<───────────────────────────────│                                │
     │                                │                                │
     │ 8. Use session for encrypted communication                      │
     │─────────────────────────────────────────────────────────────────>
```

### MSL Error Codes (Key Exchange)

| Code | Constant | Description |
|------|----------|-------------|
| 7000 | - | Unable to identify key exchange scheme |
| 7001 | - | No factory registered for key exchange scheme |
| 7003 | - | Unable to identify key exchange key ID |

### Key Files for Analysis

| File | Class | Purpose |
|------|-------|---------|
| `com/netflix/ale/AleService.java` | AleService | Key provisioning entry |
| `com/netflix/ale/KeyExchangeRsaOaep.java` | KeyExchangeRsaOaep | RSA key exchange |
| `com/netflix/ale/AleCryptoBouncyCastle.java` | AleCryptoBouncyCastle | Crypto operations |
| `o/C18406hvS.java` | MSL Agent | MSL client impl |
| `o/InterfaceC18394hvG.java` | MSL Interface | MSL client interface |
| `o/C28733mum.java` | Error codes | MSL error definitions |

### Security Notes

1. **RSA-OAEP-256** - Strong asymmetric encryption
2. **Session tokens** - Time-limited with TTL
3. **Key wrapping** - Server wraps session key with client's public key
4. **JWE** - JSON Web Encryption for session data

## Next Steps

- [x] Trace MSL key exchange flow
- [x] Find API endpoints in obfuscated code
- [x] Analyze certificate pinning implementation
- [x] Document ESN (device ID) generation

---

## API Endpoints

### WebSocket Endpoints

#### Push Notifications
| Environment | URL |
|-------------|-----|
| Production | `wss://push.prod.netflix.com/ws` |
| Production (Android) | `wss://android.push.prod.netflix.com/ws` |
| Staging | `wss://ws.push.staging.netflix.com/ws` |
| Test | `wss://ws.test.netflix.com/ws` |

**File:** `o/C11315fAv.java`

#### NRDP (Netflix Ready Device Platform)
| Environment | URL |
|-------------|-----|
| Production (ALE) | `wss://nrdp.ws.ale.netflix.com/socketrouter` |
| Experimental | `wss://nrdp.ws.exp.netflix.com/socketrouter` |
| Test | `wss://nrdp.ws.ale.test.netflix.net/socketrouter` |

**File:** `o/fAC.java`

#### Play Exchange (Streaming)
| Environment | URL |
|-------------|-----|
| Production | `wss://android.ws.prod.cloud.netflix.com/playexchange` |
| Staging | `wss://android.ws.staging.cloud.netflix.com/playexchange` |
| Test | `wss://android.ws.test.cloud.netflix.com/playexchange` |

**File:** `o/fAC.java`

### HTTP Endpoints

| Purpose | URL |
|---------|-----|
| Logging/Analytics | `https://ichnaea.staging.netflix.com/cl2` |
| Help Center | `https://help.netflix.com/mobilechat` |
| Device Error API | `https://help.netflix.com/api/deviceerror` |
| OAuth Init | `https://app.netflix.com/oAuth2Init` |
| Age Verification | `https://www.netflix.com/verifyage` |
| Login Help | `https://www.netflix.com/loginhelp` |
| Terms of Use | `https://www.netflix.com/termsofuse` |
| Privacy | `https://www.netflix.com/privacy` |
| Change Plan | `https://www.netflix.com/changeplan` |

### Appboot (Cleartext Allowed)
```
android-appboot.netflix.com
appboot.netflix.com
```

---

## Certificate Pinning Analysis

### Network Security Config
**File:** `res/xml/2132213766.xml` (referenced in AndroidManifest)

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="@raw/2131951625"/>  <!-- Netflix RSA CA -->
            <certificates src="@raw/2131951626"/>  <!-- Netflix ECC CA -->
            <certificates src="system"/>
        </trust-anchors>
    </base-config>
    
    <!-- Block cleartext for common TLDs -->
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">com</domain>
        <domain includeSubdomains="true">net</domain>
        <domain includeSubdomains="true">gov</domain>
        <domain includeSubdomains="true">edu</domain>
        <domain includeSubdomains="true">org</domain>
        <domain includeSubdomains="true">mil</domain>
    </domain-config>
    
    <!-- Allow cleartext for appboot -->
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">android-appboot.netflix.com</domain>
        <domain includeSubdomains="true">appboot.netflix.com</domain>
    </domain-config>
</network-security-config>
```

### Custom CA Certificates

#### Certificate 1: RSA Root CA
**File:** `res/raw/2131951625`
```
Issuer: Netflix Inc, Platform Security
CN: Primary CA RSA 4096 G4 2023
Key: RSA 4096-bit
Valid: 2001 - 2047
Location: Los Gatos, California, US
```

#### Certificate 2: ECC Root CA
**File:** `res/raw/2131951626`
```
Issuer: Netflix
CN: PRIMARY ROOT CA ECC P384 G4a 2024
Key: ECC P-384
Valid: 2001 - 2047
```

### TrustManager Implementation

Netflix uses custom TrustManager implementations:

| File | Purpose |
|------|---------|
| `o/C29579nge.java` | Default TrustManager factory |
| `o/C29576ngb.java` | TrustManager with default algorithm |
| `o/C29581ngg.java` | X509TrustManagerExtensions wrapper |
| `o/C29521nfZ.java` | BouncyCastle PKIX TrustManager |
| `org/chromium/net/X509Util.java` | Chromium network stack trust |

### Bypass Strategies

1. **Modify network_security_config.xml**
   - Add `<certificates src="user"/>` to trust user-installed certs
   - Set `cleartextTrafficPermitted="true"` globally

2. **Replace CA certificates**
   - Replace `res/raw/2131951625` and `2131951626` with custom CA

3. **Frida hooks**
   - Hook TrustManager.checkServerTrusted()
   - Hook X509TrustManagerExtensions

4. **Patch APK**
   - Modify network security config
   - Repackage and resign

### Security Notes

- Netflix uses **custom root CAs** (not public CAs)
- Both **RSA 4096** and **ECC P-384** certificates
- **Appboot** endpoints allow cleartext (for initial bootstrap)
- System certificates are also trusted (allows some flexibility)

---

## License Response Structure (Captured)

### Protobuf Format

Netflix license response menggunakan custom protobuf wrapper:

```
Field 1 (varint): 2                    # Message type
Field 2 (nested): License Container
  ├── Field 1: Session Info
  │   ├── Field 1: Session ID (16 bytes)
  │   └── Field 2: JSON Metadata
  │       {
  │         "version": "1.0",
  │         "esn": "NFCDIE-03-...",
  │         "issuetime": 1768550603,
  │         "movieid": "81697775",
  │         "salt": "283781366..."
  │       }
  ├── Field 2: License Config
  │   ├── Field 4: License Duration (900 sec)
  │   └── Field 5: Renewal Window (43200 sec)
  ├── Field 3: Key Container (repeated)
  │   ├── Field 1: KID (16 bytes)
  │   ├── Field 2: Encrypted Key (16 bytes)
  │   └── Field 3: IV (16 bytes)
  └── Field 6: Token Info
      {
        "tokenId": "735380826...",
        "sequenceNumber": 4
      }
Field 3: Signature (32 bytes)
Field 4: Encrypted Data (128 bytes)
Field 7: CDM Version ("19.15.0")
```

### Extracted Key Data

```
Key 1:
  KID: 9645486ccbd05cdbaaddfe47275203ac
  Key: cfbc04c16994ffae97c6afc699fb2457... (encrypted)

Key 2:
  KID: 00000000092ea8970000000000000000
  Key: c795ccc81e00e4f0d3546ec5447ffbb5 (encrypted)
  IV:  4ca7b1244ef15dfbb285ce7d0ab3991b

Key 3:
  KID: 00000000092ea8940000000000000000
  Key: c82f76c14dd2f0b24ca39eed1e861689 (encrypted)
  IV:  b2b7fcaf1af73b771d66dd29017c89a2
```

### Key Decryption Requirements

Keys masih **encrypted** dengan session key. Untuk decrypt:

1. **CDM Device Files** - `client_id_blob` + `private_key`
2. **Session Key** - Derived dari license challenge + CDM private key
3. **AES-CBC Decrypt** - Menggunakan session key dan IV

### ESN Format (Browser)

```
NFCDIE-03-L22QT2MHJFN5XKEKR080EP6FL0UQ67

NFCDIE = Netflix Chrome Desktop IE (Edge)
03 = Version/Type
L22QT2MHJFN5XKEKR080EP6FL0UQ67 = Unique device identifier
```

---

## ESN (Electronic Serial Number) Generation

### Overview
ESN adalah unique identifier untuk setiap device yang digunakan Netflix untuk:
- Device binding (DRM license)
- Quality control (4K eligibility)
- Concurrent stream tracking
- Security/fraud detection

### ESN Format

```
NFANDROID[X]-PRV-[TYPE]-[LEVEL]-[DEVICE_INFO]

Contoh:
NFANDROID1-PRV-S-L3-SAMSU_SM-G998BS_<UNIQUE_ID>
NFANDROIDD-PRV-S-L3-...  (Debug variant)
```

**Components:**
| Part | Description |
|------|-------------|
| `NFANDROID1` | Platform identifier (Android) |
| `PRV` | Provisioning type |
| `S` | Device type (S=Standard) |
| `L3` / `L1` | Widevine security level |
| `SAMSU` | Manufacturer (5 chars, uppercase) |
| `SM-G998B` | Model (max 45 chars) |
| `S` | Suffix |
| `<UNIQUE_ID>` | Device unique identifier |

### Key Files

| File | Class | Purpose |
|------|-------|---------|
| `o/fHN.java` | DeviceIdentityUtils | ESN component generation |
| `o/C11533fIy.java` | PROXY-ESN | ESN storage & caching |
| `o/C11459fGd.java` | DrmMetricsCollector | DRM metrics with ESN |
| `o/C11463fGh.java` | - | ESN prefix validation |

### ESN Generation Flow

```java
// 1. Get Manufacturer (5 chars, padded)
String manufacturer = Build.MANUFACTURER;  // e.g., "samsung"
if (manufacturer.length() < 5) {
    manufacturer = manufacturer + "     ";  // pad with spaces
}
manufacturer = manufacturer.substring(0, 5).toUpperCase();
manufacturer = manufacturer.replace("_", "");  // "SAMSU"

// 2. Get Model (max 45 chars)
String model = Build.MODEL;  // e.g., "SM-G998B"
if (model.length() > 45) {
    model = model.substring(0, 45);
}
model = model.replace("_", "");

// 3. Build device part
String devicePart = manufacturer + model + "S";  // "SAMSU_SM-G998BS"

// 4. Get Unique ID
String androidId = Settings.Secure.getString(
    context.getContentResolver(), 
    "android_id"
);
// Fallback: generate random UUID if android_id null
if (androidId == null) {
    androidId = UUID.randomUUID().toString();
    // Store in SharedPrefs: "nf_rnd_device_id"
}

// 5. Hash/encode unique ID
String uniqueId = hashAndEncode(androidId);

// 6. Final ESN
String esn = "NFANDROID1-PRV-S-L3-" + devicePart + uniqueId;
```

### ESN Storage

```java
// SharedPreferences keys:
"nf_drm_esn"        // Current ESN
"nf_drm_proxy_esn"  // Cached ESN with metadata (JSON)
"nf_rnd_device_id"  // Fallback random device ID

// Proxy ESN JSON format:
{
    "esn": "NFANDROID1-PRV-S-L3-...",
    "ts": 1234567890,  // timestamp
    "sn": 12345        // sequence number
}
```

### ESN Migration

Netflix supports ESN migration between Widevine levels:

| Migration Type | From | To |
|---------------|------|-----|
| ESN_MIGRATION_L1_2_L3 | L1 | L3 |
| ESN_MIGRATION_L3_2_L3 | L3 | L3 |
| ESN_MIGRATION_L1_2_L1 | L1 | L1 |
| ESN_MIGRATION_L3_2_L1 | L3 | L1 |
| ESN_MIGRATION_LEGACY_2_L1 | Legacy | L1 |

### ESN Validation

```java
// Check if ESN is L3 type
boolean isL3Esn(String esn) {
    return esn.startsWith("NFANDROID1-PRV-S-L3-") 
        || esn.startsWith("NFANDROIDD-PRV-S-L3-");
}
```

### HTTP Headers

ESN dikirim dalam HTTP headers:
```
X-Netflix.esn: NFANDROID1-PRV-S-L3-SAMSU_SM-G998BS_...
X-Netflix.esnPrefix: NFANDROID1-PRV-S-L3-SAMSU
```

### Security Implications

1. **ESN tied to Widevine** - Cannot fake L1 ESN on L3 device
2. **Server validation** - Netflix validates ESN format & device info
3. **Blacklisting** - Invalid/suspicious ESN gets blocked
4. **Mismatch detection** - `MSL_ESN_MISMATCH` error if ESN changes unexpectedly
