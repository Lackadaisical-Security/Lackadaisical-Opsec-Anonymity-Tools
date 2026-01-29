/**
 * Browser Fingerprint Spoofer
 * Part of Lackadaisical Anonymity Toolkit
 * 
 * Modifies browser fingerprinting vectors to prevent tracking
 */

(function() {
    'use strict';
    
    // Configuration
    const config = {
        spoofCanvas: true,
        spoofWebGL: true,
        spoofAudio: true,
        spoofTimezone: true,
        spoofLanguage: true,
        spoofHardware: true,
        spoofFonts: true,
        randomize: true
    };
    
    // Generate random seed for consistent spoofing
    const seed = config.randomize ? Math.random() : 0.5;
    
    // Canvas fingerprinting protection
    if (config.spoofCanvas) {
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        const originalToBlob = HTMLCanvasElement.prototype.toBlob;
        const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
        
        HTMLCanvasElement.prototype.toDataURL = function() {
            const context = this.getContext('2d');
            const imageData = context.getImageData(0, 0, this.width, this.height);
            
            // Add noise to image data
            for (let i = 0; i < imageData.data.length; i += 4) {
                imageData.data[i] += Math.floor((Math.random() - 0.5) * 4);
                imageData.data[i + 1] += Math.floor((Math.random() - 0.5) * 4);
                imageData.data[i + 2] += Math.floor((Math.random() - 0.5) * 4);
            }
            
            context.putImageData(imageData, 0, 0);
            return originalToDataURL.apply(this, arguments);
        };
        
        CanvasRenderingContext2D.prototype.getImageData = function() {
            const imageData = originalGetImageData.apply(this, arguments);
            
            // Add consistent noise based on seed
            for (let i = 0; i < imageData.data.length; i += 4) {
                const noise = (seed * (i + 1)) % 3 - 1;
                imageData.data[i] += noise;
                imageData.data[i + 1] += noise;
                imageData.data[i + 2] += noise;
            }
            
            return imageData;
        };
    }
    
    // WebGL fingerprinting protection
    if (config.spoofWebGL) {
        const getParameterProxied = new Proxy(WebGLRenderingContext.prototype.getParameter, {
            apply: function(target, thisArg, args) {
                const parameter = args[0];
                const result = Reflect.apply(target, thisArg, args);
                
                // Spoof common WebGL parameters
                switch (parameter) {
                    case thisArg.VENDOR:
                        return 'Intel Inc.';
                    case thisArg.RENDERER:
                        return 'Intel Iris OpenGL Engine';
                    case thisArg.MAX_TEXTURE_SIZE:
                        return 4096;
                    case thisArg.MAX_VIEWPORT_DIMS:
                        return new Int32Array([4096, 4096]);
                    default:
                        return result;
                }
            }
        });
        
        WebGLRenderingContext.prototype.getParameter = getParameterProxied;
        if (window.WebGL2RenderingContext) {
            WebGL2RenderingContext.prototype.getParameter = getParameterProxied;
        }
    }
    
    // Audio fingerprinting protection
    if (config.spoofAudio) {
        const audioContext = window.AudioContext || window.webkitAudioContext;
        if (audioContext) {
            const originalCreateOscillator = audioContext.prototype.createOscillator;
            const originalCreateDynamicsCompressor = audioContext.prototype.createDynamicsCompressor;
            
            audioContext.prototype.createOscillator = function() {
                const oscillator = originalCreateOscillator.apply(this, arguments);
                const originalConnect = oscillator.connect;
                
                oscillator.connect = function() {
                    // Add slight frequency variation
                    oscillator.frequency.value *= (1 + (seed - 0.5) * 0.0001);
                    return originalConnect.apply(this, arguments);
                };
                
                return oscillator;
            };
        }
    }
    
    // Timezone spoofing
    if (config.spoofTimezone) {
        const timezoneOffset = Math.floor(seed * 24 - 12) * 60;
        
        Date.prototype.getTimezoneOffset = function() {
            return timezoneOffset;
        };
        
        Intl.DateTimeFormat.prototype.resolvedOptions = new Proxy(
            Intl.DateTimeFormat.prototype.resolvedOptions,
            {
                apply: function(target, thisArg, args) {
                    const options = Reflect.apply(target, thisArg, args);
                    options.timeZone = 'UTC';
                    return options;
                }
            }
        );
    }
    
    // Language spoofing
    if (config.spoofLanguage) {
        Object.defineProperty(navigator, 'language', {
            get: function() {
                const languages = ['en-US', 'en-GB', 'de-DE', 'fr-FR', 'es-ES'];
                return languages[Math.floor(seed * languages.length)];
            }
        });
        
        Object.defineProperty(navigator, 'languages', {
            get: function() {
                return [navigator.language];
            }
        });
    }
    
    // Hardware spoofing
    if (config.spoofHardware) {
        Object.defineProperty(navigator, 'hardwareConcurrency', {
            get: function() {
                return 4 + Math.floor(seed * 4);
            }
        });
        
        Object.defineProperty(navigator, 'deviceMemory', {
            get: function() {
                return Math.pow(2, 2 + Math.floor(seed * 3));
            }
        });
        
        Object.defineProperty(screen, 'width', {
            get: function() {
                const widths = [1366, 1440, 1920, 2560];
                return widths[Math.floor(seed * widths.length)];
            }
        });
        
        Object.defineProperty(screen, 'height', {
            get: function() {
                const heights = [768, 900, 1080, 1440];
                return heights[Math.floor(seed * heights.length)];
            }
        });
    }
    
    // Font fingerprinting protection
    if (config.spoofFonts) {
        const fontList = [
            'Arial', 'Verdana', 'Times New Roman', 'Georgia', 'Courier New',
            'Comic Sans MS', 'Impact', 'Lucida Console', 'Tahoma', 'Trebuchet MS'
        ];
        
        const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
        CanvasRenderingContext2D.prototype.measureText = function(text) {
            const metrics = originalMeasureText.apply(this, arguments);
            
            // Add slight variation to font metrics
            return new Proxy(metrics, {
                get: function(target, prop) {
                    if (prop === 'width') {
                        return target[prop] * (1 + (seed - 0.5) * 0.001);
                    }
                    return target[prop];
                }
            });
        };
    }
    
    // Battery API spoofing
    if (navigator.getBattery) {
        navigator.getBattery = function() {
            return Promise.resolve({
                charging: true,
                chargingTime: 0,
                dischargingTime: Infinity,
                level: 0.99,
                addEventListener: function() {},
                removeEventListener: function() {}
            });
        };
    }
    
    // WebRTC IP leak protection
    if (window.RTCPeerConnection) {
        const originalRTCPeerConnection = window.RTCPeerConnection;
        
        window.RTCPeerConnection = function(configuration) {
            if (configuration && configuration.iceServers) {
                configuration.iceServers = [];
            }
            return new originalRTCPeerConnection(configuration);
        };
        
        window.RTCPeerConnection.prototype = originalRTCPeerConnection.prototype;
    }
    
    // Notification of spoofing active
    console.log('Lackadaisical Fingerprint Spoofer: Active');
})();

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        name: 'Lackadaisical Fingerprint Spoofer',
        version: '1.0.0',
        author: 'Lackadaisical Security'
    };
}
