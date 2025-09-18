# Port Forwarding Guide for Chatterbox

To allow internet connections to your Chatterbox app, you need to configure port forwarding on your router.

## Quick Setup Guide:

### 1. Find Your Router's Admin Panel
- Open a web browser
- Go to your router's IP (usually `192.168.1.1` or `192.168.0.1`)
- Login with admin credentials

### 2. Configure Port Forwarding
- Look for "Port Forwarding", "Virtual Server", or "Applications & Gaming"
- Add a new rule:
  - **Service Name**: Chatterbox
  - **Port Range**: 41235-41235 (both start and end)
  - **Protocol**: TCP
  - **Internal IP**: Your local IP (shown in Chatterbox app)
  - **Internal Port**: 41235
  - **Enable**: Yes

### 3. Test the Connection
- Save the settings and restart your router
- Give your public IP to friends (shown in Chatterbox app)
- They can connect using "Manual IP" mode with your public IP

## Router-Specific Guides:

### Netgear
1. Advanced → Port Forwarding
2. Add Custom Service
3. Enter details above

### Linksys
1. Smart Wi-Fi Tools → Port Forwarding
2. Add new forwarding rule
3. Enter details above

### TP-Link
1. Advanced → NAT Forwarding → Port Forwarding
2. Add new rule
3. Enter details above

### ASUS
1. WAN → Port Forwarding
2. Enable Port Forwarding: Yes
3. Add rule with details above

## Security Notes:
- Only forward the specific port (41235)
- Consider using a VPN for secure connections
- Monitor your router logs for security
- Disable port forwarding when not needed

## Alternative Solutions:
- **VPN**: Set up a VPN server for secure remote access
- **Dynamic DNS**: Use services like DuckDNS for consistent addressing
- **Tunneling**: Use tools like ngrok for temporary public access