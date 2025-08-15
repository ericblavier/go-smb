# SMBv1/SMBv2 Negotiation Test Program

This test program demonstrates and tests the SMBv1 negotiation fixes implemented in the go-smb library.

## Building

```bash
go build -o smb-test main.go
```

## Usage

### Basic Usage (Test Negotiation Only)

```bash
# Test negotiation with a local SMB server
./smb-test -host 192.168.1.100

# Test with debug output
./smb-test -host 192.168.1.100 -debug

# Test on non-standard port
./smb-test -host 192.168.1.100 -port 139
```

### With Authentication

```bash
# Test with credentials (will also test authentication)
./smb-test -host 192.168.1.100 -user Administrator -pass MyPassword123

# Test with domain credentials
./smb-test -host 192.168.1.100 -user Administrator -pass MyPassword123 -domain MYDOMAIN

# Test with debug logging
./smb-test -host 192.168.1.100 -user testuser -pass testpass -debug
```

## Command Line Options

- `-host` - Target host IP address (default: 127.0.0.1)
- `-port` - Target port (default: 445)
- `-user` - Username for authentication test (optional)
- `-pass` - Password for authentication test (optional)
- `-domain` - Domain for authentication test (optional)
- `-debug` - Enable debug logging

## What It Tests

### 1. SMB Protocol Negotiation
The program tests the newly implemented SMBv1/SMBv2 negotiation logic:
- Sends SMB1 negotiate request with SMB2 dialects
- Properly handles SMB1 responses that indicate SMB2 support
- Falls back to SMB2 negotiation when appropriate
- Shows selected protocol dialect and capabilities

### 2. Authentication (if credentials provided)
- Tests NTLM authentication
- Shows authentication status
- Tests basic share connection (IPC$)

## Expected Output

### Successful Negotiation
```
=== SMBv1/SMBv2 Negotiation Test ===
Target: 192.168.1.100:445
Debug: false
=====================================

🔄 Testing SMB Protocol Negotiation (Anonymous)...
✅ SMB connection established to 192.168.1.100:445
   🔐 Signing: Optional
✅ Anonymous negotiation successful!

✅ All tests completed!
```

### With Authentication
```
=== SMBv1/SMBv2 Negotiation Test ===
Target: 192.168.1.100:445
Debug: false
=====================================

🔄 Testing SMB Protocol Negotiation (Anonymous)...
✅ SMB connection established to 192.168.1.100:445
   🔐 Signing: Optional
✅ Anonymous negotiation successful!

🔐 Testing SMB Authentication...
✅ SMB session established successfully
✅ Login successful as Administrator
   🔐 Signing: Optional
📁 Testing IPC$ share connection...
✅ IPC$ share connection successful

✅ All tests completed!
```

## Testing Different Server Types

This program is particularly useful for testing the SMBv1 negotiation fixes with:

1. **Servers that support both SMBv1 and SMBv2** (Windows 2008/2012/2016 with SMBv1 enabled)
2. **Servers that only support SMBv2** (Modern Windows, Samba 4.x)
3. **Legacy servers that only support SMBv1** (Old Windows versions, some NAS devices)

The program will show different behavior depending on what the server supports, demonstrating that the negotiation logic correctly handles all scenarios.

## Troubleshooting

- If connection fails immediately: Check if port 445 is open
- If negotiation fails: Server may not support any common SMB dialects
- If authentication fails: Check credentials and domain settings
- Use `-debug` flag for detailed protocol traces
