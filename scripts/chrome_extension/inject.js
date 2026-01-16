// Widevine EME Interceptor - Educational Purpose Only
// Hooks Encrypted Media Extensions API to capture license exchange

(function() {
    'use strict';
    
    const LOG_PREFIX = '[WV-Intercept]';
    const capturedData = {
        pssh: [],
        licenseRequests: [],
        licenseResponses: [],
        keys: []
    };

    // Helper: ArrayBuffer to Hex
    function bufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    // Helper: ArrayBuffer to Base64
    function bufferToBase64(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    }

    // Helper: Extract PSSH from init data
    function extractPSSH(initData) {
        const data = new Uint8Array(initData);
        const psshBoxes = [];
        let offset = 0;
        
        while (offset < data.length) {
            const size = (data[offset] << 24) | (data[offset+1] << 16) | 
                        (data[offset+2] << 8) | data[offset+3];
            const type = String.fromCharCode(data[offset+4], data[offset+5], 
                                            data[offset+6], data[offset+7]);
            
            if (type === 'pssh') {
                psshBoxes.push(bufferToBase64(data.slice(offset, offset + size)));
            }
            offset += size;
            if (size === 0) break;
        }
        return psshBoxes;
    }

    // Hook: navigator.requestMediaKeySystemAccess
    const originalRequestMKSA = navigator.requestMediaKeySystemAccess.bind(navigator);
    navigator.requestMediaKeySystemAccess = async function(keySystem, configs) {
        console.log(`${LOG_PREFIX} requestMediaKeySystemAccess:`, keySystem);
        
        const access = await originalRequestMKSA(keySystem, configs);
        
        // Wrap createMediaKeys
        const originalCreateMediaKeys = access.createMediaKeys.bind(access);
        access.createMediaKeys = async function() {
            const mediaKeys = await originalCreateMediaKeys();
            return wrapMediaKeys(mediaKeys);
        };
        
        return access;
    };

    // Wrap MediaKeys
    function wrapMediaKeys(mediaKeys) {
        const originalCreateSession = mediaKeys.createSession.bind(mediaKeys);
        
        mediaKeys.createSession = function(sessionType) {
            const session = originalCreateSession(sessionType);
            return wrapMediaKeySession(session);
        };
        
        return mediaKeys;
    }

    // Wrap MediaKeySession
    function wrapMediaKeySession(session) {
        // Hook generateRequest
        const originalGenerateRequest = session.generateRequest.bind(session);
        session.generateRequest = async function(initDataType, initData) {
            console.log(`${LOG_PREFIX} generateRequest:`, initDataType);
            
            const psshList = extractPSSH(initData);
            psshList.forEach(pssh => {
                console.log(`${LOG_PREFIX} PSSH (Base64):`, pssh);
                capturedData.pssh.push({
                    timestamp: Date.now(),
                    type: initDataType,
                    pssh: pssh
                });
            });
            
            return originalGenerateRequest(initDataType, initData);
        };

        // Hook update (license response)
        const originalUpdate = session.update.bind(session);
        session.update = async function(response) {
            console.log(`${LOG_PREFIX} License Response received`);
            console.log(`${LOG_PREFIX} Response (Hex):`, bufferToHex(response).substring(0, 200) + '...');
            
            capturedData.licenseResponses.push({
                timestamp: Date.now(),
                response: bufferToBase64(response)
            });
            
            // Parse keys from response (simplified)
            try {
                parseKeysFromResponse(response);
            } catch(e) {
                console.log(`${LOG_PREFIX} Key parse error:`, e);
            }
            
            return originalUpdate(response);
        };

        // Listen for message event (license request)
        const originalAddEventListener = session.addEventListener.bind(session);
        session.addEventListener = function(type, listener, options) {
            if (type === 'message') {
                const wrappedListener = function(event) {
                    console.log(`${LOG_PREFIX} License Request generated`);
                    console.log(`${LOG_PREFIX} Request (Hex):`, bufferToHex(event.message).substring(0, 200) + '...');
                    
                    capturedData.licenseRequests.push({
                        timestamp: Date.now(),
                        messageType: event.messageType,
                        message: bufferToBase64(event.message)
                    });
                    
                    listener(event);
                };
                return originalAddEventListener(type, wrappedListener, options);
            }
            return originalAddEventListener(type, listener, options);
        };

        return session;
    }

    // Parse keys from license response (basic Widevine parsing)
    function parseKeysFromResponse(response) {
        const data = new Uint8Array(response);
        // Widevine license response parsing is complex
        // This is a simplified version - real parsing needs protobuf
        
        console.log(`${LOG_PREFIX} Response size: ${data.length} bytes`);
        
        // Look for key patterns (16 bytes key ID + 16 bytes key)
        // Real implementation would use protobuf parsing
    }

    // Export captured data
    window.WV_CAPTURED = capturedData;
    
    // Console command to dump data
    window.dumpWVData = function() {
        console.log(`${LOG_PREFIX} === CAPTURED DATA ===`);
        console.log(JSON.stringify(capturedData, null, 2));
        return capturedData;
    };

    console.log(`${LOG_PREFIX} Interceptor loaded. Use dumpWVData() to see captured data.`);
})();
