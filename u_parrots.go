package tls

import (
	"crypto/sha256"
	"errors"
	"io"
	"runtime"
)

func (c *ExtendedConfig) parrotDefault() error {
	switch runtime.GOOS {
	case "windows":
		fallthrough
	case "darwin":
		fallthrough
	case "linux":
		fallthrough
	default:
		fallthrough
	case "android":
		return c.parrotByID(ParrotAndroid_5_1_Browser)
	}
}

func (c *ExtendedConfig) parrotByID(id ParrotID) error {
	c.ParrotID = id
	switch c.ParrotID {
	case ParrotFirefox_Latest:
		fallthrough
	case ParrotFirefox_53_WIP:
		/*
			Work in progress!
			TODO: double check session id generation
			TODO: add firefox-style padding
		*/
		c.Hello.Vers = VersionTLS12

		if len(c.Hello.Random) != 32 {
			c.Hello.Random = make([]byte, 32)
			_, err := io.ReadFull(c.config.rand(), c.Hello.Random)
			if err != nil {
				return errors.New("tls: short read from Rand: " + err.Error())
			}
		}
		c.Hello.CipherSuites = []uint16{
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
			FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		}
		c.Hello.CompressionMethods = []uint8{compressionNone}

		sni := SNIExtension{c.config.ServerName}
		ems := FakeExtendedMasterSecretExtension{}
		reneg := RenegotiationInfoExtension{renegotiation: RenegotiateOnceAsClient}
		curves := SupportedCurvesExtension{[]CurveID{X25519, CurveP256, CurveP384, CurveP521}}
		points := SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}}
		sessionTicket := SessionTicketExtension{Session: c.Session}
		if c.Session != nil {
			sessionTicket.Session = c.Session
			if len(c.Session.SessionTicket()) > 0 {
				c.Hello.SessionId = make([]byte, 32)
				_, err := io.ReadFull(c.config.rand(), c.Hello.SessionId)
				if err != nil {
					return errors.New("tls: short read from Rand: " + err.Error())
				}
			}
		}
		alpn := ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
		status := StatusRequestExtension{}
		sigAndHash := SignatureAlgorithmsExtension{SignatureAndHashes: []SignatureAndHash{
			{hashSHA256, signatureECDSA},
			{hashSHA384, signatureECDSA},
			{disabledHashSHA512, signatureECDSA},
			fakeRsaPssSha256,
			fakeRsaPssSha384,
			fakeRsaPssSha512,
			{hashSHA256, signatureRSA},
			{hashSHA384, signatureRSA},
			{disabledHashSHA512, signatureRSA},
			{hashSHA1, signatureECDSA},
			{hashSHA1, signatureRSA}},
		}
		c.Extensions = []TLSExtension{
			&sni,
			&ems,
			&reneg,
			&curves,
			&points,
			&sessionTicket,
			&alpn,
			&status,
			&sigAndHash,
		}
	case ParrotAndroid_Latest:
		fallthrough
	case ParrotAndroid_6_0_Browser:
		c.Hello.Vers = VersionTLS12

		if len(c.Hello.Random) != 32 {
			c.Hello.Random = make([]byte, 32)
			_, err := io.ReadFull(c.config.rand(), c.Hello.Random)
			if err != nil {
				return errors.New("tls: short read from Rand: " + err.Error())
			}
		}
		appendToCipherSuites(&cipherSuite{OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12,
			ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305})
		appendToCipherSuites(&cipherSuite{OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12,
			ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12, nil, nil, aeadChaCha20Poly1305})
		c.Hello.CipherSuites = []uint16{
			OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_AES_128_GCM_SHA256,
			TLS_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
		}
		c.Hello.CompressionMethods = []uint8{compressionNone}

		sni := SNIExtension{c.config.ServerName}
		ems := FakeExtendedMasterSecretExtension{}
		sessionTicket := SessionTicketExtension{Session: c.Session}
		if c.Session != nil {
			sessionTicket.Session = c.Session
			if len(c.Session.SessionTicket()) > 0 {
				sessionId := sha256.Sum256(c.Session.SessionTicket())
				c.Hello.SessionId = sessionId[:]
			}
		}
		appendToSigAlgs(disabledHashSHA512, signatureRSA)
		appendToSigAlgs(disabledHashSHA512, signatureECDSA)
		sigAndHash := SignatureAlgorithmsExtension{SignatureAndHashes: []SignatureAndHash{
			{disabledHashSHA512, signatureRSA},
			{disabledHashSHA512, signatureECDSA},
			{hashSHA384, signatureRSA},
			{hashSHA384, signatureECDSA},
			{hashSHA256, signatureRSA},
			{hashSHA256, signatureECDSA},
			{fakeHashSHA224, signatureRSA},
			{fakeHashSHA224, signatureECDSA},
			{hashSHA1, signatureRSA},
			{hashSHA1, signatureECDSA}},
		}
		status := StatusRequestExtension{}
		npn := NPNExtension{}
		sct := SCTExtension{}
		alpn := ALPNExtension{AlpnProtocols: []string{"http/1.1", "spdy/8.1"}}
		points := SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}}
		curves := SupportedCurvesExtension{[]CurveID{CurveP256, CurveP384}}
		padding := FakePaddingExtension{GetPadingLen: boringPaddingStyle}

		c.Extensions = []TLSExtension{
			&sni,
			&ems,
			&sessionTicket,
			&sigAndHash,
			&status,
			&npn,
			&sct,
			&alpn,
			&points,
			&curves,
			&padding,
		}
	case ParrotAndroid_5_1_Browser:
		c.Hello.Vers = VersionTLS12

		if len(c.Hello.Random) != 32 {
			c.Hello.Random = make([]byte, 32)
			_, err := io.ReadFull(c.config.rand(), c.Hello.Random)
			if err != nil {
				return errors.New("tls: short read from Rand: " + err.Error())
			}
		}
		appendToCipherSuites(&cipherSuite{OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12,
			ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305})
		appendToCipherSuites(&cipherSuite{OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12,
			ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12, nil, nil, aeadChaCha20Poly1305})
		c.Hello.CipherSuites = []uint16{
			OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			TLS_RSA_WITH_AES_128_GCM_SHA256,
			TLS_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_RC4_128_SHA,
			FAKE_TLS_RSA_WITH_RC4_128_MD5,
			TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
		}
		c.Hello.CompressionMethods = []uint8{compressionNone}

		sni := SNIExtension{c.config.ServerName}
		sessionTicket := SessionTicketExtension{Session: c.Session}
		if c.Session != nil {
			sessionTicket.Session = c.Session
			if len(c.Session.SessionTicket()) > 0 {
				sessionId := sha256.Sum256(c.Session.SessionTicket())
				c.Hello.SessionId = sessionId[:]
			}
		}
		appendToSigAlgs(disabledHashSHA512, signatureRSA)
		appendToSigAlgs(disabledHashSHA512, signatureECDSA)
		sigAndHash := SignatureAlgorithmsExtension{SignatureAndHashes: []SignatureAndHash{
			{disabledHashSHA512, signatureRSA},
			{disabledHashSHA512, signatureECDSA},
			{hashSHA384, signatureRSA},
			{hashSHA384, signatureECDSA},
			{hashSHA256, signatureRSA},
			{hashSHA256, signatureECDSA},
			{fakeHashSHA224, signatureRSA},
			{fakeHashSHA224, signatureECDSA},
			{hashSHA1, signatureRSA},
			{hashSHA1, signatureECDSA}},
		}
		status := StatusRequestExtension{}
		npn := NPNExtension{}
		sct := SCTExtension{}
		alpn := ALPNExtension{AlpnProtocols: []string{"http/1.1", "spdy/3", "spdy/3.1"}}
		points := SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}}
		curves := SupportedCurvesExtension{[]CurveID{CurveP256, CurveP384, CurveP521}}
		padding := FakePaddingExtension{GetPadingLen: boringPaddingStyle}

		c.Extensions = []TLSExtension{
			&sni,
			&sessionTicket,
			&sigAndHash,
			&status,
			&npn,
			&sct,
			&alpn,
			&points,
			&curves,
			&padding,
		}
	case ParrotChrome_Latest:
		fallthrough
	case ParrotChrome_58:
		c.Hello.Vers = VersionTLS12

		if len(c.Hello.Random) != 32 {
			c.Hello.Random = make([]byte, 32)
			_, err := io.ReadFull(c.config.rand(), c.Hello.Random)
			if err != nil {
				return errors.New("tls: short read from Rand: " + err.Error())
			}
		}
		c.Hello.CipherSuites = []uint16{
			GetBoringGREASEValue(c.Hello.Random, ssl_grease_cipher),
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_GCM_SHA256,
			TLS_RSA_WITH_AES_256_GCM_SHA384,
			TLS_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		}
		c.Hello.CompressionMethods = []uint8{compressionNone}

		grease_ext1 := GetBoringGREASEValue(c.Hello.Random, ssl_grease_extension1)
		grease_ext2 := GetBoringGREASEValue(c.Hello.Random, ssl_grease_extension2)
		if grease_ext1 == grease_ext2 {
			grease_ext2 ^= 0x1010
		}

		grease1 := FakeGREASEExtension{Value: grease_ext1}
		reneg := RenegotiationInfoExtension{renegotiation: RenegotiateOnceAsClient}
		sni := SNIExtension{c.config.ServerName}
		ems := FakeExtendedMasterSecretExtension{}
		sessionTicket := SessionTicketExtension{Session: c.Session}
		if c.Session != nil {
			sessionTicket.Session = c.Session
			if len(c.Session.SessionTicket()) > 0 {
				sessionId := sha256.Sum256(c.Session.SessionTicket())
				c.Hello.SessionId = sessionId[:]
			}
		}
		sigAndHash := SignatureAlgorithmsExtension{SignatureAndHashes: []SignatureAndHash{
			{hashSHA256, signatureECDSA},
			fakeRsaPssSha256,
			{hashSHA256, signatureRSA},
			{hashSHA384, signatureECDSA},
			fakeRsaPssSha384,
			{hashSHA384, signatureRSA},
			fakeRsaPssSha512,
			{disabledHashSHA512, signatureRSA},
			{hashSHA1, signatureRSA}},
		}
		status := StatusRequestExtension{}
		sct := SCTExtension{}
		alpn := ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
		channelId := FakeChannelIDExtension{}
		points := SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}}
		curves := SupportedCurvesExtension{[]CurveID{CurveID(GetBoringGREASEValue(c.Hello.Random, ssl_grease_group)),
			X25519, CurveP256, CurveP384}}
		grease2 := FakeGREASEExtension{Value: grease_ext2, Body: []byte{0}}
		padding := FakePaddingExtension{GetPadingLen: boringPaddingStyle}

		c.Extensions = []TLSExtension{
			&grease1,
			&reneg,
			&sni,
			&ems,
			&sessionTicket,
			&sigAndHash,
			&status,
			&sct,
			&alpn,
			&channelId,
			&points,
			&curves,
			&grease2,
			&padding,
		}
	}
	return nil
}
