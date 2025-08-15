package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ericblavier/go-smb/smb"
	"github.com/ericblavier/go-smb/spnego"
	"github.com/jfjallid/golog"
)

func main() {
	var host = flag.String("host", "127.0.0.1", "Target host IP address")
	var port = flag.Int("port", 445, "Target port (default: 445)")
	var username = flag.String("user", "", "Username (optional for negotiate test)")
	var password = flag.String("pass", "", "Password (optional for negotiate test)")
	var domain = flag.String("domain", "", "Domain (optional for negotiate test)")
	var debug = flag.Bool("debug", false, "Enable debug logging")
	var showDialects = flag.Bool("show-dialects", true, "Show supported SMB dialects")

	flag.Parse()

	// Set up logging
	logger := golog.Get("smb-test")
	if *debug {
		logger.Infoln("Debug logging enabled")
	}

	fmt.Printf("=== SMBv1/SMBv2 Negotiation Test ===\n")
	fmt.Printf("Target: %s:%d\n", *host, *port)
	fmt.Printf("Debug: %v\n", *debug)
	fmt.Println("=====================================")

	// Show supported dialects if requested
	if *showDialects {
		showSupportedDialects()
	}

	// Test 1: Basic connection and negotiation (anonymous)
	if err := testNegotiation(*host, *port, logger); err != nil {
		logger.Errorln("Negotiation test failed:", err)
		// Continue to test with credentials if provided
	} else {
		fmt.Println("✅ Anonymous negotiation successful!")
	}

	// Test 2: If credentials provided, test authentication
	if *username != "" {
		if err := testAuthentication(*host, *port, *username, *password, *domain, logger); err != nil {
			logger.Errorln("Authentication test failed:", err)
			os.Exit(1)
		}
	}

	fmt.Println("\n✅ All tests completed!")
}

func testNegotiation(host string, port int, logger *golog.MyLogger) error {
	fmt.Println("\n🔄 Testing SMB Protocol Negotiation...")

	// Create SMB connection with null session for negotiation test
	options := smb.Options{
		Host: host,
		Port: port,
		Initiator: &spnego.NTLMInitiator{
			User:     "",
			Password: "",
			Domain:   "",
		},
	}

	session, err := smb.NewConnection(options)
	if err != nil {
		return fmt.Errorf("failed to create connection: %v", err)
	}
	defer session.Close()

	logger.Infof("✅ SMB connection established to %s:%d", host, port)

	// Show detailed negotiation results
	showNegotiationResult(session)

	return nil
}

func testAuthentication(host string, port int, username, password, domain string, logger *golog.MyLogger) error {
	fmt.Println("\n🔐 Testing SMB Authentication...")

	// Create SMB connection with credentials
	options := smb.Options{
		Host: host,
		Port: port,
		Initiator: &spnego.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		},
	}

	session, err := smb.NewConnection(options)
	if err != nil {
		return fmt.Errorf("failed to create authenticated connection: %v", err)
	}
	defer session.Close()

	logger.Info("✅ SMB session established successfully")

	// Check authentication status
	if session.IsAuthenticated() {
		fmt.Printf("✅ Login successful as %s\n", session.GetAuthUsername())
	} else {
		return fmt.Errorf("authentication failed")
	}

	// Show detailed results
	showNegotiationResult(session)

	// Try to connect to IPC$ share to test basic functionality
	fmt.Println("📁 Testing IPC$ share connection...")
	err = session.TreeConnect("IPC$")
	if err != nil {
		return fmt.Errorf("failed to connect to IPC$ share: %v", err)
	}
	defer session.TreeDisconnect("IPC$")

	fmt.Println("✅ IPC$ share connection successful")

	return nil
}

func showSupportedDialects() {
	fmt.Println("\n📋 SMB Protocol Dialects Overview")
	fmt.Println("==================================")

	fmt.Println("\n🔄 Dialects advertised in SMB1 Negotiate Request:")
	smb1Dialects := []struct {
		index       int
		name        string
		description string
	}{
		{0, "PC NETWORK PROGRAM 1.0", "Original SMB protocol"},
		{1, "LANMAN1.0", "LAN Manager 1.0"},
		{2, "Windows for Workgroups 3.1a", "Windows for Workgroups"},
		{3, "LM1.2X002", "LAN Manager 1.2"},
		{4, "LANMAN2.1", "LAN Manager 2.1"},
		{5, "NT LM 0.12", "SMBv1 (NT LAN Manager)"},
		{6, "SMB 2.002", "SMB 2.0.2"},
		{7, "SMB 2.100", "SMB 2.1.0"},
		{8, "SMB 2.???", "SMB 2.x wildcard"},
	}

	for _, dialect := range smb1Dialects {
		var category string
		if dialect.index <= 5 {
			category = "SMBv1"
		} else {
			category = "SMBv2"
		}
		fmt.Printf("   [%d] %s %-25s (%s)\n", dialect.index, category, dialect.name, dialect.description)
	}

	fmt.Println("\n🔄 SMBv2+ Dialects supported:")
	smb2Dialects := []struct {
		hex         string
		name        string
		description string
		features    string
	}{
		{"0x0202", "SMB 2.0.2", "SMB 2.0.2", "Basic SMBv2, introduced with Vista/2008"},
		{"0x0210", "SMB 2.1.0", "SMB 2.1.0", "Improved with Windows 7/2008R2"},
		{"0x0300", "SMB 3.0.0", "SMB 3.0.0", "Encryption, Windows 8/2012"},
		{"0x0302", "SMB 3.0.2", "SMB 3.0.2", "Enhanced encryption, Windows 8.1/2012R2"},
		{"0x0311", "SMB 3.1.1", "SMB 3.1.1", "Latest features, Windows 10/2016+"},
		{"0x02FF", "SMB 2.???", "SMB 2.x Wildcard", "Multi-protocol negotiation"},
	}

	for _, dialect := range smb2Dialects {
		fmt.Printf("   %s %-12s - %s\n", dialect.hex, dialect.name, dialect.features)
	}

	fmt.Println("\n💡 Negotiation Process:")
	fmt.Println("   1. Client sends SMB1 negotiate with all dialects above")
	fmt.Println("   2. Server responds with selected dialect or SMB2 response")
	fmt.Println("   3. If SMBv2 selected, client continues with SMBv2 protocol")
	fmt.Println("")
}

func showNegotiationResult(session *smb.Connection) {
	fmt.Println("\n🎯 Negotiation Result:")

	// Get detailed signing information
	signingSupported := getSigningInfo(session, "supported")
	signingRequired := getSigningInfo(session, "required")

	// Display SMB Signing status
	fmt.Printf("   🔐 SMB Signing Supported: %s\n", formatYesNo(signingSupported))
	fmt.Printf("   🔐 SMB Signing Required: %s\n", formatYesNo(signingRequired))

	// Show authentication status
	if session.IsAuthenticated() {
		fmt.Printf("   👤 Authenticated as: %s\n", session.GetAuthUsername())
	} else {
		fmt.Println("   👤 Authentication: Anonymous/Null session")
	}
}

func getSigningInfo(session *smb.Connection, infoType string) bool {
	switch infoType {
	case "required":
		return session.IsSigningRequired()
	case "supported":
		return session.IsSigningSupported()
	default:
		return false
	}
}

func formatYesNo(value bool) string {
	if value {
		return "✅ Yes"
	}
	return "❌ No"
}

func getDialectName(dialect uint16) string {
	switch dialect {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1.0"
	case 0x0300:
		return "SMB 3.0.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	case 0x02FF:
		return "SMB 2.???"
	default:
		return "Unknown"
	}
}
