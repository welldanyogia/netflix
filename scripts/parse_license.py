#!/usr/bin/env python3
"""
Netflix License Response Parser
Parses the protobuf structure of Netflix Widevine license responses
"""

import base64
import struct
import json

def read_varint(data, offset):
    """Read a varint from data at offset, return (value, new_offset)"""
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            return result, offset
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return result, offset

def parse_protobuf(data, depth=0):
    """Parse protobuf and print structure"""
    offset = 0
    indent = "  " * depth
    results = []
    
    while offset < len(data):
        if offset >= len(data):
            break
            
        # Read field tag
        tag, offset = read_varint(data, offset)
        if tag == 0:
            break
            
        field_num = tag >> 3
        wire_type = tag & 0x07
        
        if wire_type == 0:  # Varint
            value, offset = read_varint(data, offset)
            results.append(f"{indent}Field {field_num} (varint): {value}")
            
        elif wire_type == 1:  # 64-bit
            if offset + 8 > len(data):
                break
            value = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            results.append(f"{indent}Field {field_num} (64-bit): {value}")
            
        elif wire_type == 2:  # Length-delimited
            length, offset = read_varint(data, offset)
            if offset + length > len(data):
                break
            value = data[offset:offset+length]
            offset += length
            
            # Try to decode as string
            try:
                decoded = value.decode('utf-8')
                if decoded.startswith('{') and decoded.endswith('}'):
                    results.append(f"{indent}Field {field_num} (JSON): {decoded}")
                elif decoded.isprintable():
                    results.append(f"{indent}Field {field_num} (string): {decoded[:100]}...")
                else:
                    raise ValueError()
            except:
                # Check if nested protobuf
                if len(value) > 2 and value[0] in [0x08, 0x0a, 0x10, 0x12, 0x18, 0x1a]:
                    results.append(f"{indent}Field {field_num} (nested message, {len(value)} bytes):")
                    nested = parse_protobuf(value, depth + 1)
                    results.extend(nested)
                else:
                    results.append(f"{indent}Field {field_num} (bytes, {len(value)} bytes): {value[:32].hex()}...")
                    
        elif wire_type == 5:  # 32-bit
            if offset + 4 > len(data):
                break
            value = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            results.append(f"{indent}Field {field_num} (32-bit): {value}")
        else:
            results.append(f"{indent}Field {field_num} (unknown wire type {wire_type})")
            break
            
    return results

def main():
    # License Response from captured data
    license_response_b64 = "CAIS6AQKvwEKEFTe9lzEJpxv2bzdpUqqqjcSmQF7InZlcnNpb24iOiIxLjAiLCJlc24iOiJORkNESUUtMDMtTDIyUVQyTUhKRk41WEtFS1IwODBFUDZGTDBVUTY3IiwiaXNzdWV0aW1lIjoxNzY4NTUwNjAzLCJtb3ZpZWlkIjoiODE2OTc3NzUiLCJzYWx0IjoiMjgzNzgxMzY2NjM5NzkyMzgwNTMwMDExNDE4MDExNTA4In0gASgAOIQHQMDRAkjM4afLBhIaCAEQABgBIIQHKMDRAjhzSAVYAWABeAGQAQIaVhIQlkVIbMvQXNuq3f5HJ1IDrBpAz7wEwWmU/66Xxq/GmfskV4W8yC0RpscIeY71swAMymUnOvdca4EjOIARLrUHUTvjhJc47TUoqvtxA0YSPfa57SABGlYKEAAAAAAJLqiXAAAAAAAAAAASEMeVzMgeAOTw01RuxUR/+7UaEEynsSRO8V37soXOfQqzmRsgAigCMgIIADoCCAFCEgoQa2MxNgAAAHjOsO53hAAACBpWChAAAAAACS6olAAAAAAAAAAAEhDIL3bBTdLwskyjnu0ehhaJGhCyt/yvGvc7dx1m3SkBfImiIAIoAjICCAA6AggBQhIKEGtjMTYAAAB4zrDud4QAAAggzOGnywYyQnsidG9rZW5JZCI6IjczNTM4MDgyNjgzNjc4NTk5MjA4MDkwMTkyNTY2MDg2NyIsInNlcXVlbmNlTnVtYmVyIjo0fTgAUAVoAnIwCLCk+soGEAAYACAAKhDlRLpAC8EPN9O2Nvi1T/tDMhB0ZXN0Lm5ldGZsaXguY29tGiBT3DyO7yBhA87hGvkl168pLtoAQSJ/TIwuoHcn0iR7UiKAASsuL12vN3K8KKDlrn3LQe4D+jAn2BncZXOKUarddKMKrCz6dxWG/CWC1urf76SRlKuVcFF2Y5PqP2qp6216XrtjcoIHwmnCJ5C2PkqzMmy2HzD++OEg6zOl3XJUz54sq/FnLkr2KNY2CL1a7eWoqL6mBrwkwfOS0+Km69lmluZMOgkKBzE5LjE1LjBAAUrYAQAAAAIAAADYAAUAEM6w7ncQUGIPAAAA4gAAABAAAAD0AAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAADhAAAAAAAAKjAAAAAAAAAAHgAAAACAAABOgAAABAAAAFMAAAAEAAAAV4AAAAQAAAAAAAAAAAAAAF+AAAAEAAAAZIAAAAQAAABpAAAABAAAAG2AAAAEAAAAAAAAAAAAAABfgAAABADxFamgqSlq8zV1axzjuFLR0+oTyCokx+NsSCl1wWg9VgB"
    
    print("=" * 60)
    print("Netflix License Response Analysis")
    print("=" * 60)
    
    data = base64.b64decode(license_response_b64)
    print(f"\nTotal size: {len(data)} bytes")
    print(f"First bytes (hex): {data[:20].hex()}")
    
    print("\n" + "-" * 40)
    print("Protobuf Structure:")
    print("-" * 40)
    
    results = parse_protobuf(data)
    for line in results:
        print(line)
    
    # Extract JSON metadata
    print("\n" + "-" * 40)
    print("Extracted Metadata:")
    print("-" * 40)
    
    # Find JSON in data
    try:
        start = data.find(b'{"version"')
        if start != -1:
            end = data.find(b'}', start) + 1
            json_str = data[start:end].decode('utf-8')
            metadata = json.loads(json_str)
            print(json.dumps(metadata, indent=2))
    except Exception as e:
        print(f"Error extracting JSON: {e}")

if __name__ == "__main__":
    main()
