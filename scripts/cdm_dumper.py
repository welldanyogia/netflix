#!/usr/bin/env python3
"""
Widevine L3 CDM Dumper for Chrome/Edge
Intercepts CDM initialization to extract device keys

Requirements:
- pip install frida frida-tools
- Chrome/Edge browser
"""

import frida
import sys
import os
import base64
import json
from pathlib import Path

# Frida script to hook Widevine CDM
FRIDA_SCRIPT = """
'use strict';

// Hook widevinecdm.dll functions
const moduleName = 'widevinecdm.dll';

// Wait for module to load
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
        }, 100);
    }
}

waitForModule(moduleName, (module) => {
    console.log('[+] Found ' + moduleName + ' at ' + module.base);
    console.log('[+] Size: ' + module.size);
    
    // Search for known patterns in CDM
    // The private key is typically stored after initialization
    
    // Hook CreateSession or similar functions
    const exports = module.enumerateExports();
    console.log('[+] Exports found: ' + exports.length);
    
    exports.forEach((exp) => {
        if (exp.name.includes('Session') || exp.name.includes('Key') || exp.name.includes('License')) {
            console.log('  [*] ' + exp.name + ' @ ' + exp.address);
        }
    });
    
    // Memory scan for RSA private key markers
    // PEM format starts with "-----BEGIN RSA PRIVATE KEY-----"
    // DER format starts with 0x30 0x82
    
    console.log('[+] Scanning for private key patterns...');
    
    Memory.scan(module.base, module.size, '30 82', {
        onMatch: (address, size) => {
            // Check if this looks like a DER-encoded key
            const header = Memory.readByteArray(address, 4);
            const bytes = new Uint8Array(header);
            if (bytes[0] === 0x30 && bytes[1] === 0x82) {
                const keyLen = (bytes[2] << 8) | bytes[3];
                if (keyLen > 100 && keyLen < 2000) {
                    console.log('[!] Potential private key at ' + address + ', length: ' + keyLen);
                    
                    // Read the key
                    const keyData = Memory.readByteArray(address, keyLen + 4);
                    send({type: 'private_key', address: address.toString(), data: keyData});
                }
            }
        },
        onComplete: () => {
            console.log('[+] Private key scan complete');
        }
    });
    
    // Scan for client ID blob (starts with specific pattern)
    console.log('[+] Scanning for client ID blob...');
    
    // Client ID typically contains device certificate
    Memory.scan(module.base, module.size, '08 01 12', {
        onMatch: (address, size) => {
            // Protobuf pattern for client ID
            const preview = Memory.readByteArray(address, 32);
            console.log('[!] Potential client ID at ' + address);
            send({type: 'client_id_candidate', address: address.toString(), preview: preview});
        },
        onComplete: () => {
            console.log('[+] Client ID scan complete');
        }
    });
});

// Hook specific CDM functions if symbols are available
try {
    const cdm = Process.getModuleByName(moduleName);
    
    // Try to hook OEMCrypto functions
    const symbols = cdm.enumerateSymbols();
    symbols.forEach((sym) => {
        if (sym.name.includes('OEMCrypto') || sym.name.includes('GetDeviceID')) {
            console.log('[*] Symbol: ' + sym.name + ' @ ' + sym.address);
            
            Interceptor.attach(sym.address, {
                onEnter: function(args) {
                    console.log('[>] ' + sym.name + ' called');
                },
                onLeave: function(retval) {
                    console.log('[<] ' + sym.name + ' returned: ' + retval);
                }
            });
        }
    });
} catch (e) {
    console.log('[-] Symbol enumeration failed: ' + e);
}

console.log('[+] CDM Dumper initialized. Play DRM content to trigger key extraction.');
"""

class CDMDumper:
    def __init__(self, process_name):
        self.process_name = process_name
        self.session = None
        self.script = None
        self.extracted_data = {
            'private_keys': [],
            'client_ids': []
        }
        
    def on_message(self, message, data):
        if message['type'] == 'send':
            payload = message['payload']
            
            if payload['type'] == 'private_key':
                print(f"[+] Private key found at {payload['address']}")
                self.extracted_data['private_keys'].append({
                    'address': payload['address'],
                    'data': base64.b64encode(data).decode() if data else None
                })
                
            elif payload['type'] == 'client_id_candidate':
                print(f"[+] Client ID candidate at {payload['address']}")
                self.extracted_data['client_ids'].append({
                    'address': payload['address'],
                    'preview': base64.b64encode(data).decode() if data else None
                })
                
        elif message['type'] == 'error':
            print(f"[-] Error: {message['stack']}")
            
    def attach(self):
        print(f"[*] Attaching to {self.process_name}...")
        
        try:
            self.session = frida.attach(self.process_name)
            self.script = self.session.create_script(FRIDA_SCRIPT)
            self.script.on('message', self.on_message)
            self.script.load()
            print("[+] Script loaded successfully")
            return True
        except frida.ProcessNotFoundError:
            print(f"[-] Process '{self.process_name}' not found")
            print("[*] Make sure Chrome/Edge is running")
            return False
        except Exception as e:
            print(f"[-] Error: {e}")
            return False
            
    def save_results(self, output_dir):
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save extracted data
        with open(output_path / 'extracted_data.json', 'w') as f:
            json.dump(self.extracted_data, f, indent=2)
            
        print(f"[+] Results saved to {output_dir}")
        
    def run(self):
        if not self.attach():
            return
            
        print("\n" + "=" * 50)
        print("CDM Dumper Running")
        print("=" * 50)
        print("1. Open Netflix/Prime Video in the browser")
        print("2. Play any DRM-protected content")
        print("3. Press Ctrl+C to stop and save results")
        print("=" * 50 + "\n")
        
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            print("\n[*] Stopping...")
            
        self.save_results('./cdm_dump')
        
        if self.session:
            self.session.detach()

def main():
    print("""
╔═══════════════════════════════════════════╗
║     Widevine L3 CDM Dumper                ║
║     For Educational Purposes Only         ║
╚═══════════════════════════════════════════╝
    """)
    
    # Detect browser
    browsers = {
        'chrome': 'chrome.exe',
        'edge': 'msedge.exe',
        'brave': 'brave.exe'
    }
    
    print("Select browser:")
    print("1. Chrome")
    print("2. Edge")
    print("3. Brave")
    print("4. Custom process name")
    
    choice = input("\nChoice [1-4]: ").strip()
    
    if choice == '1':
        process = 'chrome.exe'
    elif choice == '2':
        process = 'msedge.exe'
    elif choice == '3':
        process = 'brave.exe'
    elif choice == '4':
        process = input("Enter process name: ").strip()
    else:
        print("Invalid choice")
        return
        
    dumper = CDMDumper(process)
    dumper.run()

if __name__ == "__main__":
    main()
