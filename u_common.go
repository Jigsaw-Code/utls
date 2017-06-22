package tls

import "fmt"

// Naming convention:
// Unsupported things are prefixed with "Fake"
// Supported things, that have changed their ID are prefixed with "Old"
// Supported but disabled things are prefixed with "Disabled". We will _enable_ them.
const (
	fakeExtensionExtendedMasterSecret uint16 = 23
	fakeExtensionPadding              uint16 = 21    // not 'fake' per se, just to note: not supported by crypto/tls
	fakeExtensionChannelID            uint16 = 30032 // not IANA assigned
)

const (
	OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = uint16(0xcc13)
	OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc14)

	FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc15) // we can try to craft these ciphersuites
	FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           = uint16(0x009e) // from existing pieces, if needed

	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = uint16(0x0033)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA  = uint16(0x0039)
	FAKE_TLS_RSA_WITH_RC4_128_MD5          = uint16(0x0004)
	FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV = uint16(0x00ff)
)

// newest signatures
var (
	fakeRsaPssSha256 = SignatureAndHash{0x08, 0x04}
	fakeRsaPssSha384 = SignatureAndHash{0x08, 0x05}
	fakeRsaPssSha512 = SignatureAndHash{0x08, 0x06}
	// fakeEd25519 = SignatureAndHash{0x08, 0x07}
	// fakeEd448 = SignatureAndHash{0x08, 0x08}
)

// IDs of hash functions in signatures
const (
	disabledHashSHA512 uint8 = 6 // Supported, but disabled by default. Will be enabled, as needed
	fakeHashSHA224     uint8 = 3 // Supported, but we won't enable it: sounds esoteric and fishy

)

type ParrotID struct {
	Browser uint8
	Version uint16
	// TODO: consider adding OS?
}

func (p *ParrotID) Str() string {
	return fmt.Sprintf("%d-%d", p.Browser, p.Version)
}

const (
	parrotFirefox = uint8(0x06)
	parrotChrome  = uint8(0x08)
	parrotAndroid = uint8(0x01)
)

var (
	ParrotDefault ParrotID = ParrotID{0, 0}

	ParrotFirefox_Latest ParrotID = ParrotID{parrotFirefox, 0}
	ParrotFirefox_53_WIP          = ParrotID{parrotFirefox, 53}

	ParrotChrome_Latest ParrotID = ParrotID{parrotChrome, 0}
	ParrotChrome_58     ParrotID = ParrotID{parrotChrome, 58}

	ParrotAndroid_Latest      ParrotID = ParrotID{parrotAndroid, 0}
	ParrotAndroid_6_0_Browser ParrotID = ParrotID{parrotAndroid, 23}
	ParrotAndroid_5_1_Browser ParrotID = ParrotID{parrotAndroid, 22}
)

// Appends newCipher to cipherSuites, if not there already
// Used to add old cipher ids
func appendToCipherSuites(newCipher *cipherSuite) {
	for _, c := range cipherSuites {
		if c.id == newCipher.id {
			return
		}
	}
	cipherSuites = append(cipherSuites, newCipher)
}

// Appends {hash, sig} to supportedSignatureAlgorithms, if not there already
// Used to enable already supported but disabled signatures
func appendToSigAlgs(hash uint8, sig uint8) {
	s := signatureAndHash{hash, sig}
	for _, c := range supportedSignatureAlgorithms {
		if c.hash == s.hash && c.signature == s.signature {
			return
		}
	}
	supportedSignatureAlgorithms = append(supportedSignatureAlgorithms, s)
}
