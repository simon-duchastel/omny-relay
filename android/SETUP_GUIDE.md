# Android Setup Guide

## Requirements
- Android device with NFC support (Android 5.0+)
- One device must support Host Card Emulation (HCE)
- For advanced features: rooted device with Xposed framework

## NFCGate Installation
1. Download NFCGate APK from the official repository
2. Enable installation from unknown sources
3. Install the APK on your Android device(s)

## Configuration
1. Open NFCGate app
2. Go to Settings
3. Configure server connection:
   - Server hostname: [Your server IP/hostname]
   - Server port: 8080
   - Enable TLS: Yes (recommended)
   - Session ID: [6-digit session ID from server]

## Usage Modes

### Capture Mode
- Used for capturing NFC traffic from cards
- Place your transit card near the device
- Captured data will be sent to the server for analysis

### Relay Mode
- Requires two devices: Reader and Card
- Reader device: Scans the NFC card
- Card device: Emulates the card using HCE
- Server relays data between the devices

## Security Notes
- Always use TLS encryption for data transmission
- Only use for authorized research purposes
- Ensure compliance with local regulations
- Do not use on payment cards without authorization

## Troubleshooting
- Check NFC is enabled on device
- Verify network connectivity to server
- Ensure server certificate is trusted
- Check app permissions (NFC, Network)
