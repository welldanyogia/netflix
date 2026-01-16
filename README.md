# Netflix Reverse Engineering Research

Educational research project for understanding Netflix's DRM and security implementation.

## Structure

```
netflix/
├── notes/                    # Documentation & analysis
│   ├── drm_analysis.md       # DRM, MSL, ESN documentation
│   └── widevine_cdm_extraction.md  # CDM extraction guide
├── scripts/                  # Tools & scripts
│   └── chrome_extension/     # Widevine EME interceptor
├── decompiled/               # Decompiled APK (not in repo)
└── patched/                  # Modified APKs (not in repo)
```

## Topics Covered

- Widevine DRM (L1/L3)
- MSL (Message Security Layer) key exchange
- ESN (Electronic Serial Number) generation
- Certificate pinning analysis
- API endpoints discovery

## Disclaimer

This project is for **educational purposes only**. Do not use for piracy or illegal activities.
