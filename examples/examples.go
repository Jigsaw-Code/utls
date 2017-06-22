package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

var (
	dialTimeout   = time.Duration(15) * time.Second
	sessionTicket = []uint8(`Here goes phony session ticket: it even is in ASCII range
Ticket could be of any length, but for camouflage purposes it's better to use standard lengths such as 228`)
)

func getTlsClient(SNI string, addr string) (*tls.Conn, error) {
	config := tls.Config{ServerName: SNI}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("DialTimeout error: %+v", err)
	}
	tlsConn := tls.Client(dialConn, &config)
	return tlsConn, nil
}

func GetResponseDefault(SNI string, addr string) (string, error) {
	tlsConn, err := getTlsClient(SNI, addr)
	if err != nil {
		return "", err
	}
	defer tlsConn.Close()

	err = tlsConn.Handshake()
	if err != nil {
		return "", fmt.Errorf("tlsConn.Handshake() error: %+v", err)
	}
	tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + SNI + "\r\n\r\n"))
	buf := make([]byte, 14096)
	tlsConn.Read(buf)
	return string(buf), nil
}

func GetResponseParrot(SNI string, addr string, parrotId tls.ParrotID) (string, error) {
	tlsConn, err := getTlsClient(SNI, addr)
	if err != nil {
		return "", err
	}
	defer tlsConn.Close()

	extendedConf, err := tlsConn.MakeExtendedConfigParrotID(parrotId)
	if err != nil {
		return "", fmt.Errorf("tlsConn.MakeExtendedConfigParrotID(parrotId) error: %+v", err)
	}
	chs, err := extendedConf.BuildState()
	if err != nil {
		return "", fmt.Errorf("extendedConf.BuildState() error: %+v", err)
	}
	err = tlsConn.ClientHandshakeWithState(chs)
	if err != nil {
		return "", fmt.Errorf("tlsConn.ClientHandshakeWithState(chs) error: %+v", err)
	}
	tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + SNI + "\r\n\r\n"))
	buf := make([]byte, 14096)
	tlsConn.Read(buf)
	return string(buf), nil
}

func GetResponseExplicitRandom(SNI string, addr string) (string, error) {
	tlsConn, err := getTlsClient(SNI, addr)
	if err != nil {
		return "", err
	}
	defer tlsConn.Close()

	extendedConf, err := tlsConn.MakeExtendedConfig()
	if err != nil {
		return "", fmt.Errorf("tlsConn.MakeExtendedConfig() error: %+v", err)
	}
	cRandom := []byte{100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
		110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
		120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
		130, 131}
	extendedConf.SetClientRandom(cRandom)
	// Note absence of Parrot functions: client hello will be marshaled by default Golang crypto/tls
	chs, err := extendedConf.BuildState()
	if err != nil {
		return "", fmt.Errorf(" extendedConf.BuildState() error: %+v", err)
	}
	err = tlsConn.ClientHandshakeWithState(chs)
	if err != nil {
		return "", fmt.Errorf("tlsConn.ClientHandshakeWithState(chs) error: %+v", err)
	}
	// These fields are accessible regardless of setting client hello explicitly
	fmt.Printf("#> MasterSecret:\n%s", hex.Dump(chs.MasterSecret))
	fmt.Printf("#> ClientHello Random:\n%s", hex.Dump(chs.Hello.Random))
	fmt.Printf("#> ServerHello Random:\n%s", hex.Dump(chs.ServerHello.Random))

	tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + SNI + "\r\n\r\n"))
	buf := make([]byte, 14096)
	tlsConn.Read(buf)
	return string(buf), nil
}

// Note that the server will reject the fake ticket(unless you set up your server to accept them) and do full handshake
func GetResponseTicket(SNI string, addr string) (string, error) {
	tlsConn, err := getTlsClient(SNI, addr)
	if err != nil {
		return "", err
	}
	defer tlsConn.Close()

	extendedConf, err := tlsConn.MakeExtendedConfig()
	if err != nil {
		return "", fmt.Errorf("tlsConn.MakeExtendedConfig() error: %+v", err)
	}
	masterSecret := make([]byte, 48)
	copy(masterSecret, []byte("masterSecret is NOT sent over the wire")) // you may use it for real security

	// Create a session ticket that wasn't actually issued by the server.
	sessionState := tls.MakeClientSessionState(sessionTicket, uint16(tls.VersionTLS12),
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		masterSecret,
		nil, nil)

	extendedConf.SetSessionState(sessionState)
	// Note absence of Parrot functions: client hello will be marshalled by default Golang crypto/tls
	chs, err := extendedConf.BuildState()
	if err != nil {
		return "", fmt.Errorf("extendedConf.BuildState() error: %+v", err)
	}
	err = tlsConn.ClientHandshakeWithState(chs)
	if err != nil {
		return "", fmt.Errorf("tlsConn.ClientHandshakeWithState(chs) error: %+v", err)
	}
	fmt.Println("#> This is how client hello with session ticket looked:")
	fmt.Print(hex.Dump(chs.Hello.Raw))

	tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + SNI + "\r\n\r\n"))
	buf := make([]byte, 14096)
	tlsConn.Read(buf)
	return string(buf), nil
}

// Note that the server will reject the fake ticket(unless you set up your server to accept them) and do full handshake
func GetResponseTicketParrot(SNI string, addr string) (string, error) {
	tlsConn, err := getTlsClient(SNI, addr)
	if err != nil {
		return "", err
	}
	defer tlsConn.Close()

	extendedConf, err := tlsConn.MakeExtendedConfigParrot()
	if err != nil {
		return "", fmt.Errorf("tlsConn.MakeExtendedConfigParrot() error: %+v", err)
	}
	masterSecret := make([]byte, 48)
	copy(masterSecret, []byte("masterSecret is NOT sent over the wire")) // you may use it for real security

	// Create a session ticket that wasn't actually issued by the server.
	sessionState := tls.MakeClientSessionState(sessionTicket, uint16(tls.VersionTLS12),
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		masterSecret,
		nil, nil)

	_ = sessionState
	extendedConf.SetSessionState(sessionState)
	chs, err := extendedConf.BuildState()
	if err != nil {
		return "", fmt.Errorf("extendedConf.BuildState() error: %+v", err)
	}
	err = tlsConn.ClientHandshakeWithState(chs)
	if err != nil {
		return "", fmt.Errorf("tlsConn.ClientHandshakeWithState(chs) error: %+v", err)
	}

	tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + SNI + "\r\n\r\n"))
	buf := make([]byte, 14096)
	tlsConn.Read(buf)
	return string(buf), nil
}

func main() {
	var response string
	var err error
	requestSNI := "www.google.com"
	requestAddr := "172.217.11.46:443"

	response, err = GetResponseDefault(requestSNI, requestAddr)
	if err != nil {
		fmt.Printf("#> GetResponseDefault failed: %+v\n", err)
	} else {
		fmt.Printf("#> GetResponseDefault response: %+s\n", getFirstLine(response))
	}

	response, err = GetResponseParrot(requestSNI, requestAddr, tls.ParrotAndroid_5_1_Browser)
	if err != nil {
		fmt.Printf("#> GetResponseParrot failed: %+v\n", err)
	} else {
		fmt.Printf("#> GetResponseParrot response: %+s\n", getFirstLine(response))
	}

	response, err = GetResponseExplicitRandom(requestSNI, requestAddr)
	if err != nil {
		fmt.Printf("#> GetResponseExplicitRandom failed: %+v\n", err)
	} else {
		fmt.Printf("#> GetResponseExplicitRandom response: %+s\n", getFirstLine(response))
	}

	response, err = GetResponseTicket(requestSNI, requestAddr)
	if err != nil {
		fmt.Printf("#> GetResponseTicket failed: %+v\n", err)
	} else {
		fmt.Printf("#> GetResponseTicket response: %+s\n", getFirstLine(response))
	}

	response, err = GetResponseTicketParrot(requestSNI, requestAddr)
	if err != nil {
		fmt.Printf("#> GetResponseTicketParrot failed: %+v\n", err)
	} else {
		fmt.Printf("#> GetResponseTicketParrot response: %+s\n", getFirstLine(response))
	}

	return
}

func getFirstLine(s string) string {
	ss := strings.Split(s, "\r\n")
	if len(ss) == 0 {
		return ""
	} else {
		return ss[0]
	}
}
