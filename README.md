# UnsafeTLS

## Low-level access to handshake

* Read/write access to all bits of client hello message(and session ticket).  
* Read access to fields of ClientHandshakeState, which, among other things, includes ServerHello and MasterSecret.
## ClientHello fingerprinting resistance
This package allows ClientHello messages to parrot popular browsers. There are few caveats to this parroting:
 * We are forced to offer ciphersuites and tls extensions that are not supported by crypto/tls.
 This is not a problem, if you fully control the server.
 * Parroting could be imperfect, and there is no parroting beyond ClientHello.
##### Parrots that work okay

| Parrot        | Ciphers* | Signature* | Unsupported extensions            |
| ------------- | -------- | ---------- | --------------------------------- |
| Android 5.1   | low      | very low   | None                              |
| Android 6.0   | low      | very low   | Extended Master Secret**          |
| Chrome 58     | no       | low        | Extended Master Secret**, ChannelID |

\* Denotes very rough guesstimate of likelyhood that unsupported things will get echoed back by the server, visibly
breaking the connection. Again, almost irrelevant if you control the server.  
\*\* New extensions such as EMS become popular very quickly, so it's not recommended to use with servers you don't own.
As you can see, many good parrots will become available whenever EMS is implemented in crypto/tls.
##### Work-in-progress parrots
Not finished yet!

| Parrot        | Ciphers* | Signature* | Unsupported extensions            |
| ------------- | -------- | ---------- | --------------------------------- |
| Firefox 53    | low      | low        | Extended Master Secret** |

##### Custom
You can always create extended config, reorder and reconfigure the extensions the way you want.  
#### Things to implement in Golang to make parrots better
 * Extended Master Secret and ChannelID extensions
 * Enable sha512 and sha224 hashes by default
 * Implement RSA PSS signature algorithms
#### Parrots FAQ
##### Does it really look like, say, Google Chrome with all the [GREASE](https://tools.ietf.org/html/draft-davidben-tls-grease-01) and stuff?
It LGTM, but please open up Wireshark and check. If you see something — [say something](issues).
##### Aren't there side channels? Everybody knows that the ~~bird is a word~~[parrot is dead](https://people.cs.umass.edu/~amir/papers/parrot.pdf)
There sure are. If you found one that approaches practicality at line speed — [please tell us](issues).
## Fake Session Tickets
Set of provided functions is likely to change, as use-cases aren't fully worked out yet.
Currently, there is a simple function to set session ticket to any desired state:

```Golang
func (c *ExtendedConfig) SetSessionState(session *ClientSessionState)
```

Note that session tickets (fake ones or otherwise) are not reused.
It is possible to use set same cache on multiple configs to start using shared cache.

```Golang
func (c *ExtendedConfig) UseSessionCache(cache ClientSessionCache)
```

## Tests

...exist, but coverage is limited. What's covered is a conjunction of
 * TLS 1.2
 * Working parrots without any unsupported extensions (only Android 5.1 at this time)
 * Ciphersuites offered by parrot.
 * Ciphersuites supported by Golang
 * Simple conversation with reference implementation of OpenSSL.
(e.g. no automatic checks for renegotiations, parroting quality and such)

plus we test some other minor things.
Basically, current tests aim to provide a sanity check.

## Usage

 1. First, establish tcp connection and initialize Golang's tls.Client:
```Golang
    config := tls.Config{ServerName: "www.google.com"}
    dialConn, err := net.Dial("tcp", "172.217.11.46:443")
    if err != nil {
		fmt.Printf("net.Dial() failed: %+v\n", err)
        return
    }
    tlsConn := tls.Client(dialConn, &config)
```
 2. Then we have parroting options. You can opt to have no parrot:  
```Golang
    extendedConf, err := tlsConn.MakeExtendedConfig()
    if err != nil {
		fmt.Printf("tlsConn.MakeExtendedConfig() failed: %+v\n", err)
        return
    }
```
  choose default parrot(recommended) or a particular one by id:
```Golang
extendedConf, err := tlsConn.MakeExtendedConfigParrotID(tls.ParrotAndroid_5_1_Browser)
extendedConf, err := tlsConn.MakeExtendedConfigParrot()
```
 3. (Optional) At this point you can set fake session ticket, set clientHello or change extendedConf in other ways:
```Golang
    // set fake session ticket
    masterSecret := make([]byte, 48)
    copy(masterSecret, []byte("actual masterSecret to use for real security"))
    sessionTicket := []uint8("Session ticket which also isn't supposed to be in ASCII range but oh well")

    // Create a session ticket that wasn't actually issued by the server.
    sessionState := tls.MakeClientSessionState(sessionTicket, uint16(tls.VersionTLS12),
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        masterSecret,
        nil, nil)

    extendedConf.SetSessionState(sessionState)
```
 4. Build the ClientHandshakeState and perform the handshake with it:
```Golang
    chs, err := extendedConf.BuildState()
    if err != nil {
		fmt.Printf("extendedConf.BuildState() failed: %+v\n", err)
        return
    }
    err = tlsConn.ClientHandshakeWithState(chs)
    if err != nil {
		fmt.Printf("tlsConn.ClientHandshakeWithState(chs) failed: %+v\n", err)
        return
    }
```
 5. After handshake you can get access to fields of ClientHandshakeState and carry on using tlsConn in standard ways.
 