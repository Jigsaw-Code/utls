package tls

import (
	"errors"
	"io"
	"sync"
)

// Handshake runs the client handshake using given clientHandshakeState
// Requires hs.hello, and, optionally, hs.session to be set.
func (c *Conn) ClientHandshakeWithState(hs *ClientHandshakeState) error {
	// c.handshakeErr and c.handshakeComplete are protected by
	// c.handshakeMutex. In order to perform a handshake, we need to lock
	// c.in also and c.handshakeMutex must be locked after c.in.
	//
	// However, if a Read() operation is hanging then it'll be holding the
	// lock on c.in and so taking it here would cause all operations that
	// need to check whether a handshake is pending (such as Write) to
	// block.
	//
	// Thus we first take c.handshakeMutex to check whether a handshake is
	// needed.
	//
	// If so then, previously, this code would unlock handshakeMutex and
	// then lock c.in and handshakeMutex in the correct order to run the
	// handshake. The problem was that it was possible for a Read to
	// complete the handshake once handshakeMutex was unlocked and then
	// keep c.in while waiting for network data. Thus a concurrent
	// operation could be blocked on c.in.
	//
	// Thus handshakeCond is used to signal that a goroutine is committed
	// to running the handshake and other goroutines can wait on it if they
	// need. handshakeCond is protected by handshakeMutex.
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	for {
		if err := c.handshakeErr; err != nil {
			return err
		}
		if c.handshakeComplete {
			return nil
		}
		if c.handshakeCond == nil {
			break
		}

		c.handshakeCond.Wait()
	}

	// Set handshakeCond to indicate that this goroutine is committing to
	// running the handshake.
	c.handshakeCond = sync.NewCond(&c.handshakeMutex)
	c.handshakeMutex.Unlock()

	c.in.Lock()
	defer c.in.Unlock()

	c.handshakeMutex.Lock()

	// The handshake cannot have completed when handshakeMutex was unlocked
	// because this goroutine set handshakeCond.
	if c.handshakeErr != nil || c.handshakeComplete {
		panic("handshake should not have been able to complete after handshakeCond was set")
	}

	if c.isClient {
		hs.C = c
		c.handshakeErr = c.clientHandshakeWithState(hs.getPrivatePtr())
	} else {
		panic("Servers should not call ClientHandshakeWithState()")
	}
	if c.handshakeErr == nil {
		c.handshakes++
	} else {
		// If an error occurred during the hadshake try to flush the
		// alert that might be left in the buffer.
		c.flush()
	}

	if c.handshakeErr == nil && !c.handshakeComplete {
		panic("handshake should have had a result.")
	}

	// Wake any other goroutines that are waiting for this handshake to complete.
	c.handshakeCond.Broadcast()
	c.handshakeCond = nil

	return c.handshakeErr
}

// c.out.Mutex <= L; c.handshakeMutex <= L.
func (c *Conn) clientHandshakeWithState(hs *clientHandshakeState) error {
	if c.config == nil {
		c.config = &Config{}
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false

	if len(c.config.ServerName) == 0 && !c.config.InsecureSkipVerify {
		return errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range c.config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return errors.New("tls: NextProtos values too large")
	}

	var session *ClientSessionState
	sessionCache := c.config.ClientSessionCache
	cacheKey := clientSessionCacheKey(c.conn.RemoteAddr(), c.config)

	// If sessionCache is set but session itself isn't - try to retrieve session from cache
	if sessionCache != nil && hs.session != nil {
		hs.hello.ticketSupported = true
		// Session resumption is not allowed if renegotiating because
		// renegotiation is primarily used to allow a client to send a client
		// certificate, which would be skipped if session resumption occurred.
		if c.handshakes == 0 {
			// Try to resume a previously negotiated TLS session, if
			// available.
			candidateSession, ok := sessionCache.Get(cacheKey)
			if ok {
				// Check that the ciphersuite/version used for the
				// previous session are still valid.
				cipherSuiteOk := false
				for _, id := range hs.hello.cipherSuites {
					if id == candidateSession.cipherSuite {
						cipherSuiteOk = true
						break
					}
				}

				versOk := candidateSession.vers >= c.config.minVersion() &&
					candidateSession.vers <= c.config.maxVersion()
				if versOk && cipherSuiteOk {
					session = candidateSession
				}
				if session != nil {
					hs.hello.sessionTicket = session.sessionTicket
					// A random session ID is used to detect when the
					// server accepted the ticket and is resuming a session
					// (see RFC 5077).
					hs.hello.sessionId = make([]byte, 16)
					if _, err := io.ReadFull(c.config.rand(), hs.hello.sessionId); err != nil {
						return errors.New("tls: short read from Rand: " + err.Error())
					}
				}
				hs.session = session
			}
		}
	}

	if err := hs.handshake(); err != nil {
		return err
	}
	// If we had a successful handshake and hs.session is different from the one already cached - cache a new one
	if sessionCache != nil && hs.session != nil && hs.session != session {
		sessionCache.Put(cacheKey, hs.session)
	}
	return nil
}
