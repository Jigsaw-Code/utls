package tls

import (
	"errors"
	"strconv"
)

// Public fields in ExtendedConfig are allowed to be set directly, but might
//  get overwritten by other functions: please check.
type ExtendedConfig struct {
	Extensions []TLSExtension

	// Let default crypto/tls marshal client hello (c.Extensions will be ignored)
	// You can even marshal clientHello yourself into Hello.raw and set MarshalDefault = true, in which case
	// you are responsible for modifying other parts of Config and ClientHelloMsg to reflect it.
	MarshalDefault bool

	config *Config
	conn   *Conn

	/*
	* WARNING: direct usage of fields below might have side effects.
	* All structs in tls are strongly coupled and affect each other.
	* Always feel free to ApplyConfig() and check if result satisfies you
	* (e.g. that manually set config wasn't overwritten).
	* If it is all good -- proceed with MarshalClientHello() and GetStateDirectly()
	 */
	Hello        *ClientHelloMsg
	Session      *ClientSessionState
	ParrotID     ParrotID
	SessionCache ClientSessionCache
}

// Does not parrot anything, lets default crypto/tls marshal it.
// If you wish to manually specify c.Extensions - set MarshalDefault to false.
// SNI has to be already set.
func (conn *Conn) MakeExtendedConfig() (*ExtendedConfig, error) {
	econf := ExtendedConfig{}
	if conn.config == nil {
		conn.config = &Config{}
	}
	econf.conn = conn
	econf.config = conn.config
	hello, err := makeClientHello(conn.config)
	if err != nil {
		return nil, err
	}
	econf.Hello = hello.getPublicPtr()
	econf.MarshalDefault = true
	return &econf, nil
}

// Parrots given ID. The only error it currently returns is "short read from Rand"
func (conn *Conn) MakeExtendedConfigParrotID(parrotID ParrotID) (*ExtendedConfig, error) {
	var err error
	econf := ExtendedConfig{}
	if conn.config == nil {
		conn.config = &Config{}
	}
	econf.conn = conn
	econf.config = conn.config
	econf.Hello = &ClientHelloMsg{}
	if parrotID == ParrotDefault {
		err = econf.parrotDefault()
	} else {
		err = econf.parrotByID(parrotID)
	}
	if err != nil {
		return nil, err
	}
	return &econf, nil
}

// Parrots given ID. The only error it currently returns is "short read from Rand"
func (conn *Conn) MakeExtendedConfigParrot() (*ExtendedConfig, error) {
	return conn.MakeExtendedConfigParrotID(ParrotDefault)
}

// If you want you session tickets to be reused - use same cache on following connections
func (c *ExtendedConfig) SetSessionState(session *ClientSessionState) {
	c.Session = session
	if session != nil {
		c.Hello.SessionTicket = session.sessionTicket
	}
	c.Hello.TicketSupported = true
	for _, ext := range c.Extensions {
		st, ok := ext.(*SessionTicketExtension)
		if ok {
			st.Session = session
		}
	}
}

// If you want you session tickets to be reused - use same cache on following connections
func (c *ExtendedConfig) UseSessionCache(cache ClientSessionCache) {
	c.SessionCache = cache
	c.config.ClientSessionCache = cache
	c.Hello.TicketSupported = true
}

// r has to be 32 bytes long
func (c *ExtendedConfig) SetClientRandom(r []byte) error {
	if len(r) != 32 {
		return errors.New("Incorrect client random length! Expected: 32, got: " + strconv.Itoa(len(r)))
	} else {
		copy(c.Hello.Random, r)
		return nil
	}
}

func (c *ExtendedConfig) SetSNI(sni string) {
	hname := hostnameInSNI(sni)
	c.config.ServerName = hname
	for _, ext := range c.Extensions {
		sniExt, ok := ext.(*SNIExtension)
		if ok {
			sniExt.ServerName = hname
		}
	}
}

// Applies current settings to config, marshals everything and builds
// ClientHandshakeState, ready to be used in HandshakeWithClientState().
// If your use-case isn't possible - please file an issue or PR.
func (c *ExtendedConfig) BuildState() (*ClientHandshakeState, error) {
	if !c.MarshalDefault {
		err := c.ApplyConfig()
		if err != nil {
			return nil, err
		}
		err = c.MarshalClientHello()
		if err != nil {
			return nil, err
		}
	}

	return c.GetStateDirectly(), nil
}

// Most callers just need BuildState()
func (c *ExtendedConfig) ApplyConfig() error {
	for _, ext := range c.Extensions {
		err := ext.writeToExtendedConfig(c)
		if err != nil {
			return err
		}
	}
	return nil
}

// Most callers just need BuildState()
func (c *ExtendedConfig) MarshalClientHello() error {
	headerLength := 2 + 32 + 1 + len(c.Hello.SessionId) +
		2 + len(c.Hello.CipherSuites)*2 +
		1 + len(c.Hello.CompressionMethods)

	extensionsLen := 0 // 2 bytes for length
	var paddingExt *FakePaddingExtension
	for _, ext := range c.Extensions {
		if pe, ok := ext.(*FakePaddingExtension); !ok {
			// If not padding - just add length of extension to total length
			extensionsLen += ext.Len()
		} else {
			// If padding - process it later
			if paddingExt == nil {
				paddingExt = pe
			} else {
				return errors.New("Multiple padding extensions!")
			}
		}
	}

	if paddingExt != nil {
		// determine padding extension presence and length
		paddingExt.Update(headerLength + extensionsLen) // TODO: double check the lengths
		extensionsLen += paddingExt.Len()
	}

	totalLength := headerLength + 2 + extensionsLen // 2 bytes reserved for the extensions' length itself
	x := make([]byte, 4+totalLength)

	x[0] = typeClientHello

	x[1] = uint8(totalLength >> 16)
	x[2] = uint8(totalLength >> 8)
	x[3] = uint8(totalLength)

	x[4] = uint8(c.Hello.Vers >> 8)
	x[5] = uint8(c.Hello.Vers)

	copy(x[6:38], c.Hello.Random)

	x[38] = uint8(len(c.Hello.SessionId))
	copy(x[39:39+len(c.Hello.SessionId)], c.Hello.SessionId)
	y := x[39+len(c.Hello.SessionId):]

	y[0] = uint8(len(c.Hello.CipherSuites) >> 7)
	y[1] = uint8(len(c.Hello.CipherSuites) << 1)
	for i, suite := range c.Hello.CipherSuites {
		y[2+i*2] = uint8(suite >> 8)
		y[3+i*2] = uint8(suite)
	}

	y = y[2+len(c.Hello.CipherSuites)*2:]

	y[0] = uint8(len(c.Hello.CompressionMethods))
	copy(y[1:], c.Hello.CompressionMethods)
	z := y[1+len(c.Hello.CompressionMethods):]

	if len(c.Extensions) > 0 {
		z[0] = byte(uint8(extensionsLen >> 8))
		z[1] = byte(uint8(extensionsLen))
		z = z[2:]

		for _, ext := range c.Extensions {
			err := ext.writeToExtendedConfig(c)
			if err != nil {
				return err
			}
			n, err := ext.Read(z)
			if err != nil {
				return err
			}
			z = z[n:]
		}
	}
	c.Hello.Raw = x[:4+totalLength]
	return nil
}

// Returns current state as-is. You probably want to build it first.
func (c *ExtendedConfig) GetStateDirectly() *ClientHandshakeState {
	chs := ClientHandshakeState{}
	chs.Hello = c.Hello
	chs.Session = c.Session
	return &chs
}
