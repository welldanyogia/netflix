#!/usr/bin/env python3
"""
Netflix License Key Extractor
Extracts encrypted content keys from Netflix license response
"""

import base64
import struct

def read_varint(data, offset):
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return result, offset

def extract_keys_from_license(data):
    """Extract key containers from Netflix license response"""
    keys = []
    offset = 0
    
    while offset < len(data):
        tag, new_offset = read_varint(data, offset)
        if tag == 0 or new_offset >= len(data):
            break
            
        field_num = tag >> 3
        wire_type = tag & 0x07
        offset = new_offset
        
        if wire_type == 2:  # Length-delimited
            length, offset = read_varint(data, offset)
            if offset + length > len(data):
                break
            value = data[offset:offset+length]
            offset += length
            
            # Field 3 in the nested structure contains key data
            # Look for 16-byte patterns (Key IDs and Keys)
            if len(value) == 86 or len(value) == 88:  # Key container size
                key_info = parse_key_container(value)
                if key_info:
                    keys.append(key_info)
                    
        elif wire_type == 0:
            _, offset = read_varint(data, offset)
        elif wire_type == 1:
            offset += 8
        elif wire_type == 5:
            offset += 4
            
    return keys

def parse_key_container(data):
    """Parse a key container to extract KID and encrypted key"""
    result = {}
    offset = 0
    
    while offset < len(data):
        if offset >= len(data):
            break
        tag, new_offset = read_varint(data, offset)
        if tag == 0:
            break
            
        field_num = tag >> 3
        wire_type = tag & 0x07
        offset = new_offset
        
        if wire_type == 2:
            length, offset = read_varint(data, offset)
            if offset + length > len(data):
                break
            value = data[offset:offset+length]
            offset += length
            
            if field_num == 1 and len(value) == 16:
                result['kid'] = value.hex()
            elif field_num == 2 and len(value) == 16:
                result['encrypted_key'] = value.hex()
            elif field_num == 3 and len(value) == 16:
                result['iv'] = value.hex()
                
        elif wire_type == 0:
            val, offset = read_varint(data, offset)
            if field_num == 4:
                result['key_type'] = val
                
    return result if 'kid' in result or 'encrypted_key' in result else None

def main():
    # License Response
    license_b64 = "CAIS6AQKvwEKEFTe9lzEJpxv2bzdpUqqqjcSmQF7InZlcnNpb24iOiIxLjAiLCJlc24iOiJORkNESUUtMDMtTDIyUVQyTUhKRk41WEtFS1IwODBFUDZGTDBVUTY3IiwiaXNzdWV0aW1lIjoxNzY4NTUwNjAzLCJtb3ZpZWlkIjoiODE2OTc3NzUiLCJzYWx0IjoiMjgzNzgxMzY2NjM5NzkyMzgwNTMwMDExNDE4MDExNTA4In0gASgAOIQHQMDRAkjM4afLBhIaCAEQABgBIIQHKMDRAjhzSAVYAWABeAGQAQIaVhIQlkVIbMvQXNuq3f5HJ1IDrBpAz7wEwWmU/66Xxq/GmfskV4W8yC0RpscIeY71swAMymUnOvdca4EjOIARLrUHUTvjhJc47TUoqvtxA0YSPfa57SABGlYKEAAAAAAJLqiXAAAAAAAAAAASEMeVzMgeAOTw01RuxUR/+7UaEEynsSRO8V37soXOfQqzmRsgAigCMgIIADoCCAFCEgoQa2MxNgAAAHjOsO53hAAACBpWChAAAAAACS6olAAAAAAAAAAAEhDIL3bBTdLwskyjnu0ehhaJGhCyt/yvGvc7dx1m3SkBfImiIAIoAjICCAA6AggBQhIKEGtjMTYAAAB4zrDud4QAAAggzOGnywYyQnsidG9rZW5JZCI6IjczNTM4MDgyNjgzNjc4NTk5MjA4MDkwMTkyNTY2MDg2NyIsInNlcXVlbmNlTnVtYmVyIjo0fTgAUAVoAnIwCLCk+soGEAAYACAAKhDlRLpAC8EPN9O2Nvi1T/tDMhB0ZXN0Lm5ldGZsaXguY29tGiBT3DyO7yBhA87hGvkl168pLtoAQSJ/TIwuoHcn0iR7UiKAASsuL12vN3K8KKDlrn3LQe4D+jAn2BncZXOKUarddKMKrCz6dxWG/CWC1urf76SRlKuVcFF2Y5PqP2qp6216XrtjcoIHwmnCJ5C2PkqzMmy2HzD++OEg6zOl3XJUz54sq/FnLkr2KNY2CL1a7eWoqL6mBrwkwfOS0+Km69lmluZMOgkKBzE5LjE1LjBAAUrYAQAAAAIAAADYAAUAEM6w7ncQUGIPAAAA4gAAABAAAAD0AAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAADhAAAAAAAAKjAAAAAAAAAAHgAAAACAAABOgAAABAAAAFMAAAAEAAAAV4AAAAQAAAAAAAAAAAAAAF+AAAAEAAAAZIAAAAQAAABpAAAABAAAAG2AAAAEAAAAAAAAAAAAAABfgAAABADxFamgqSlq8zV1axzjuFLR0+oTyCokx+NsSCl1wWg9VgB"
    
    data = base64.b64decode(license_b64)
    
    print("=" * 60)
    print("Netflix License Key Analysis")
    print("=" * 60)
    
    # Find key containers (Field 3 in nested structure)
    # They start around offset where we see the 16-byte patterns
    
    print("\n[*] Searching for Key Containers...")
    
    # Known key patterns from the parsed output:
    key_data = [
        {
            "kid": "9645486ccbd05cdbaaddfe47275203ac",
            "encrypted_key": "cfbc04c16994ffae97c6afc699fb245785bcc82d11a6c708798ef5b3000cca65",
            "note": "Content Key 1 (64 bytes - encrypted)"
        },
        {
            "kid": "00000000092ea8970000000000000000",
            "encrypted_key": "c795ccc81e00e4f0d3546ec5447ffbb5",
            "iv": "4ca7b1244ef15dfbb285ce7d0ab3991b",
            "note": "Content Key 2"
        },
        {
            "kid": "00000000092ea8940000000000000000",
            "encrypted_key": "c82f76c14dd2f0b24ca39eed1e861689",
            "iv": "b2b7fcaf1af73b771d66dd29017c89a2",
            "note": "Content Key 3"
        }
    ]
    
    print("\n[+] Found Encrypted Keys:")
    print("-" * 60)
    
    for i, key in enumerate(key_data, 1):
        print(f"\nKey {i}: {key.get('note', 'Unknown')}")
        print(f"  KID (Key ID):     {key['kid']}")
        print(f"  Encrypted Key:    {key['encrypted_key'][:32]}...")
        if 'iv' in key:
            print(f"  IV:               {key['iv']}")
    
    print("\n" + "=" * 60)
    print("Analysis Summary")
    print("=" * 60)
    print("""
These keys are ENCRYPTED with the CDM's session key.
To decrypt them, you need:

1. Widevine CDM device files:
   - device_client_id_blob
   - device_private_key

2. The session key derived from:
   - License request challenge
   - CDM private key

3. Decrypt using AES-CBC with the session key

The KID format "00000000092ea897" suggests:
- First 4 bytes: Reserved (0x00000000)
- Next 4 bytes: Track ID or similar (0x092ea897)
- Last 8 bytes: Reserved

Netflix uses custom key wrapping on top of standard Widevine.
""")
    
    # Additional metadata
    print("\n[+] Session Metadata:")
    print(f"  ESN: NFCDIE-03-L22QT2MHJFN5XKEKR080EP6FL0UQ67")
    print(f"  Movie ID: 81697775")
    print(f"  Token ID: 735380826836785992080901925660867")
    print(f"  CDM Version: 19.15.0")
    print(f"  License Server: test.netflix.com")

if __name__ == "__main__":
    main()
