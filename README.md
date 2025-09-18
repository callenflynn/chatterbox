# Chatterbox

A secure peer-to-peer chat application with end-to-end encryption and network discovery.

## Features

- Direct peer-to-peer communication without servers
- End-to-end encryption with AES-256-GCM
- Automatic network discovery and manual IP connection
- Cross-platform compatibility (Windows, macOS, Linux)
- Modern chat interface with security indicators
- Fallback support for plain-text P2P applications

## Quick Start

### Download & Run
Download the latest executable from releases or run from source:

```bash
pip install pycryptodome netifaces
python chatterbox.py
```

### Connect
1. Set your display name
2. Use network discovery to find peers automatically
3. Or connect manually using IP addresses
4. Verify security fingerprints for encrypted connections

## Security

Chatterbox provides military-grade security:
- **AES-256-GCM encryption** for all messages
- **Diffie-Hellman key exchange** for secure session establishment
- **Peer verification** with cryptographic fingerprints
- **Visual warnings** for unverified connections

When connecting to non-Chatterbox applications, clear security warnings are displayed.

## Requirements

- Python 3.7+ (if running from source)
- Network connectivity between peers
- Ports 41234 (discovery) and 41235 (chat) accessible

## License

MIT License 