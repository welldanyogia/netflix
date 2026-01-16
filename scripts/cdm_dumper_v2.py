#!/usr/bin/env python3
"""
Widevine L3 CDM Dumper - Fixed for multi-process browsers
"""

import frida
import sys
import base64
import json
from pathlib import Path

FRIDA_SCRIPT = """
'use strict';

const moduleName = 'widevinecdm.dll';

function waitForModule(name, callback) {
    const module = Process.findModuleByName(name);
    if (module) {
        callback(module);
    } else {
        const interval = setInterval(() => {
            const m = Process.findModuleByName(name);
            if (m) {
                clearInterval(interval);
                callback(m);
            }
        }, 500);
    }
}

console.log('[*] Waiting for ' + moduleName + '...');

waitForModule(moduleName, (module) => {
    console.log('[+] Found ' + moduleName + ' at ' + module.base);
    console.log('[+] Size: ' + module.size);
    
    // Scan for RSA private key (DER format: 30 82)
    console.log('[+] Scanning for private key...');
    
    Memory.scan(module.base, module.size, '30 82', {
        onMatch: (address, size) => {
            const header = Memory.readByteArray(address, 4);
            const bytes = new Uint8Array(header);
            if (bytes[0] === 0x30 && bytes[1] === 0x82) {
                const keyLen = (bytes[2] << 8) | bytes[3];
                if (keyLen > 500 && keyLen < 2000) {
                    console.log('[!] Private key candidate at ' + address + ', len: ' + keyLen);
                    const keyData = Memory.readByteArray(address, keyLen + 4);
                    send({type: 'private_key', data: keyData});
                }
            }
        },
        onComplete: () => console.log('[+] Key scan done')
    });
    
    // Scan for client ID (protobuf: 08 01 12)
    Memory.scan(module.base, module.size, '08 01 12', {
        onMatch: (address, size) => {
            try {
                const data = Memory.readByteArray(address, 1024);
                send({type: 'client_id', data: data});
                console.log('[!] Client ID candidate at ' + address);
            } catch(e) {}
        },
        onComplete: () => console.log('[+] Client ID scan done')
    });
});

console.log('[+] Dumper ready. Play DRM content now!');
"""

class CDMDumper:
    def __init__(self):
        self.keys = []
        self.client_ids = []
        
    def on_message(self, message, data):
        if message['type'] == 'send':
            payload = message['payload']
            if payload['type'] == 'private_key' and data:
                self.keys.append(base64.b64encode(data).decode())
                print(f"[+] Captured private key ({len(data)} bytes)")
            elif payload['type'] == 'client_id' and data:
                self.client_ids.append(base64.b64encode(data).decode())
                print(f"[+] Captured client ID candidate")
        elif message['type'] == 'error':
            print(f"[-] Error: {message.get('stack', message)}")
            
    def save(self):
        Path('cdm_dump').mkdir(exist_ok=True)
        with open('cdm_dump/extracted.json', 'w') as f:
            json.dump({'keys': self.keys, 'client_ids': self.client_ids}, f, indent=2)
        print(f"\n[+] Saved to cdm_dump/extracted.json")
        print(f"    Keys: {len(self.keys)}, Client IDs: {len(self.client_ids)}")

def list_processes(name_filter):
    """List processes matching filter"""
    processes = []
    for proc in frida.enumerate_processes():
        if name_filter.lower() in proc.name.lower():
            processes.append(proc)
    return processes

def main():
    print("""
╔═══════════════════════════════════════════╗
║     Widevine L3 CDM Dumper v2             ║
╚═══════════════════════════════════════════╝
    """)
    
    # Find Edge processes
    print("[*] Searching for Edge processes...")
    procs = list_processes('msedge')
    
    if not procs:
        print("[-] No Edge processes found. Open Edge first!")
        return
        
    print(f"\n[+] Found {len(procs)} Edge processes:\n")
    
    # Sort by PID, show largest memory ones (likely main/renderer)
    for i, p in enumerate(procs[:15]):
        print(f"  {i+1}. PID {p.pid:6} - {p.name}")
    
    print("\n[*] CDM biasanya di proses dengan memory besar")
    print("[*] Coba attach ke beberapa PID, atau ketik 'all' untuk scan semua")
    
    choice = input("\nPilih nomor (1-15) atau 'all': ").strip()
    
    dumper = CDMDumper()
    
    if choice.lower() == 'all':
        pids = [p.pid for p in procs]
    else:
        try:
            idx = int(choice) - 1
            pids = [procs[idx].pid]
        except:
            print("Invalid choice")
            return
    
    for pid in pids:
        try:
            print(f"\n[*] Attaching to PID {pid}...")
            session = frida.attach(pid)
            script = session.create_script(FRIDA_SCRIPT)
            script.on('message', dumper.on_message)
            script.load()
            print(f"[+] Attached to PID {pid}")
        except Exception as e:
            print(f"[-] Failed PID {pid}: {e}")
            continue
    
    print("\n" + "="*50)
    print("Dumper running! Play Netflix video now.")
    print("Press Ctrl+C to stop and save.")
    print("="*50)
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
        
    dumper.save()

if __name__ == "__main__":
    main()
