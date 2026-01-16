#!/usr/bin/env python3
"""
Widevine CDM Dumper v3 - Auto-detect CDM process
"""

import frida
import sys
import base64
import json
import time
from pathlib import Path

FRIDA_SCRIPT = """
'use strict';

const moduleName = 'widevinecdm.dll';
const module = Process.findModuleByName(moduleName);

if (module) {
    send({type: 'found', base: module.base.toString(), size: module.size});
    
    // Scan for private key
    Memory.scan(module.base, module.size, '30 82', {
        onMatch: (address, size) => {
            const header = Memory.readByteArray(address, 4);
            const bytes = new Uint8Array(header);
            if (bytes[0] === 0x30 && bytes[1] === 0x82) {
                const keyLen = (bytes[2] << 8) | bytes[3];
                if (keyLen > 500 && keyLen < 2000) {
                    const keyData = Memory.readByteArray(address, keyLen + 4);
                    send({type: 'key', len: keyLen}, keyData);
                }
            }
        },
        onComplete: () => send({type: 'scan_done'})
    });
} else {
    send({type: 'not_found'});
}
"""

class Dumper:
    def __init__(self):
        self.keys = []
        self.found = False
        
    def on_message(self, message, data):
        if message['type'] == 'send':
            p = message['payload']
            if p['type'] == 'found':
                print(f"  [+] CDM found! Base: {p['base']}, Size: {p['size']}")
                self.found = True
            elif p['type'] == 'key' and data:
                print(f"  [!] KEY FOUND! ({p['len']} bytes)")
                self.keys.append(base64.b64encode(data).decode())
            elif p['type'] == 'not_found':
                pass
            elif p['type'] == 'scan_done':
                print(f"  [+] Scan complete")

def main():
    print("""
╔═══════════════════════════════════════════╗
║  Widevine CDM Dumper v3 - Auto Detect     ║
╚═══════════════════════════════════════════╝
""")
    
    print("[*] Scanning ALL processes for widevinecdm.dll...")
    print("[*] Buka Netflix dan play video jika belum\n")
    
    device = frida.get_local_device()
    dumper = Dumper()
    cdm_pids = []
    
    # Scan all processes
    for proc in device.enumerate_processes():
        try:
            session = frida.attach(proc.pid)
            script = session.create_script(FRIDA_SCRIPT)
            script.on('message', dumper.on_message)
            script.load()
            time.sleep(0.1)
            
            if dumper.found:
                print(f"\n[+] CDM FOUND in: {proc.name} (PID: {proc.pid})")
                cdm_pids.append(proc.pid)
                dumper.found = False
                
            session.detach()
        except Exception as e:
            pass
    
    if cdm_pids:
        print(f"\n{'='*50}")
        print(f"[+] CDM processes: {cdm_pids}")
        print(f"[+] Keys found: {len(dumper.keys)}")
        
        if dumper.keys:
            Path('cdm_dump').mkdir(exist_ok=True)
            with open('cdm_dump/keys.json', 'w') as f:
                json.dump(dumper.keys, f, indent=2)
            print(f"[+] Saved to cdm_dump/keys.json")
            
            # Save as binary
            for i, key in enumerate(dumper.keys):
                with open(f'cdm_dump/key_{i}.der', 'wb') as f:
                    f.write(base64.b64decode(key))
            print(f"[+] Saved {len(dumper.keys)} key files")
    else:
        print("\n[-] CDM not found in any process")
        print("[*] Make sure Netflix video is playing!")

if __name__ == "__main__":
    main()
