package proxied

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"crypto/rand"
)

// NewProxiedTransport returns a http.RoundTripper that wraps http.DefaultTransport
// using the provided proxy for all requests.
//
// It supports Digest authentication for proxies, in addition to all proxies
// supported by http.DefaultTransport.
func NewProxiedTransport(proxy *url.URL) http.RoundTripper {
	if proxy == nil || proxy.User == nil || (proxy.Scheme != "http" && proxy.Scheme != "https") {
		return baseTransport(proxy)
	}

	noAuth := *proxy
	noAuth.User = nil

	var tr transport
	tr.proxy = proxy
	tr.transport = baseTransport(&noAuth)
	tr.tlsTransport = baseTransport(nil)
	tr.wrapDialContext()

	return &tr
}

func baseTransport(proxy *url.URL) *http.Transport {
	var proxyFunc func(*http.Request) (*url.URL, error)
	if proxy != nil {
		proxyFunc = http.ProxyURL(proxy)
	}

	if tr, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = tr.Clone()
		tr.Proxy = proxyFunc
		return tr
	}

	return &http.Transport{
		Proxy: proxyFunc,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

type transport struct {
	proxy        *url.URL
	transport    *http.Transport
	tlsTransport *http.Transport

	auth struct {
		mx        sync.Mutex
		typ       string
		realm     string
		nonce     string
		opaque    string
		algorithm string
		qop       string
		nc        uint32
	}
}

func (tr *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		return tr.tlsTransport.RoundTrip(req)
	}
	return tr.doRoundTrip(req, tr.transport)
}

func (tr *transport) wrapDialContext() {
	// store the default DialContext
	dialContext := tr.tlsTransport.DialContext

	// and wrap it
	tr.tlsTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialContext(ctx, network, tr.proxy.Host)
		if err != nil {
			return nil, err
		}

		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}

		res, err := tr.doRoundTrip(req, &connectRoundTripper{ctx, conn})
		if err != nil {
			conn.Close()
			return nil, err
		}
		if res.StatusCode != http.StatusOK {
			conn.Close()
			return nil, errors.New(http.StatusText(res.StatusCode))
		}
		return conn, nil
	}
}

func (tr *transport) doRoundTrip(req *http.Request, rt http.RoundTripper) (*http.Response, error) {
	if auth, err := tr.authorize(req, ""); err != nil {
		return nil, err
	} else if auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}

	res, err := rt.RoundTrip(req)
	if res != nil && res.StatusCode == http.StatusProxyAuthRequired {
		if err := res.Body.Close(); err != nil {
			return nil, err
		}

		if auth, err := tr.authorize(req, res.Header.Get("Proxy-Authenticate")); err != nil {
			return nil, err
		} else if auth != "" && auth != req.Header.Get("Proxy-Authorization") {
			req.Header.Set("Proxy-Authorization", auth)
			return rt.RoundTrip(req)
		}
	}
	return res, err
}

func (tr *transport) authorize(req *http.Request, authenticate string) (string, error) {
	// if tr.proxy == nil || tr.proxy.User == nil {
	// 	return ""
	// }

	username := tr.proxy.User.Username()
	password, _ := tr.proxy.User.Password()

	tr.auth.mx.Lock()
	defer tr.auth.mx.Unlock()

	// parse authenticate header
	if authenticate != "" {
		s := strings.SplitN(authenticate, " ", 2)
		tr.auth.typ = s[0]

		if tr.auth.typ == "Digest" {
			for _, i := range parseList(s[1]) {
				s := strings.SplitN(i, "=", 2)
				if len(s) < 2 {
					continue
				}

				s[1] = strings.TrimPrefix(s[1], `"`)
				s[1] = strings.TrimSuffix(s[1], `"`)

				switch s[0] {
				case "realm":
					tr.auth.realm = s[1]
				case "nonce":
					tr.auth.nonce = s[1]
				case "opaque":
					tr.auth.opaque = s[1]
				case "algorithm":
					tr.auth.algorithm = s[1]
				case "qop":
					tr.auth.qop = s[1]
				}
			}
		}
	}

	// we don't have a saved authentication type, but are secure, so try Basic
	if tr.auth.typ == "" && tr.proxy.Scheme == "https" {
		tr.auth.typ = "Basic"
	}

	var response string

	switch tr.auth.typ {
	case "Basic":
		auth := username + ":" + password
		response = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))

	case "Digest":
		if tr.auth.algorithm != "" && tr.auth.algorithm != "MD5" {
			return "", errors.New("Digest authentication: unsupported algorithm")
		}
		if tr.auth.qop != "" && tr.auth.qop != "auth" {
			return "", errors.New("Digest authentication: unsupported quality of protection")
		}

		ha1 := getMD5(username, tr.auth.realm, password) // OK
		ha2 := getMD5(req.Method, req.URL.String())      // OK

		if tr.auth.qop == "" {
			response = fmt.Sprintf(
				`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
				username, tr.auth.realm, tr.auth.nonce, req.URL, // escape these
				getMD5(ha1, tr.auth.nonce, ha2))
		} else {
			tr.auth.nc += 1
			cnonce := getNonce()
			nc := fmt.Sprintf("%08x", tr.auth.nc)

			response = fmt.Sprintf(
				`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", nc=%s, cnonce="%s", qop=%s`,
				username, tr.auth.realm, tr.auth.nonce, req.URL, // escape these
				getMD5(ha1, tr.auth.nonce, nc, cnonce, tr.auth.qop, ha2),
				nc, cnonce, tr.auth.qop)
		}

		if tr.auth.algorithm != "" {
			response = response + `, algorithm=` + tr.auth.algorithm
		}
		if tr.auth.opaque != "" {
			response = response + `, opaque="` + tr.auth.opaque + `"` // escape
		}
	}

	return response, nil
}

type connectRoundTripper struct {
	ctx  context.Context
	conn net.Conn
}

// adapted from: https://pkg.go.dev/net/http#Transport
func (rt *connectRoundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	// If there's no done channel (no deadline or cancellation
	// from the caller possible), at least set some (long)
	// timeout here. This will make sure we don't block forever
	// and leak a goroutine if the connection stops replying
	// after the TCP connect.
	ctx := rt.ctx
	if ctx.Done() == nil {
		newCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
		defer cancel()
		ctx = newCtx
	}

	readDone := make(chan struct{}) // closed after CONNECT write+read is done or fails
	// Write the CONNECT request & read the response.
	go func() {
		defer close(readDone)
		err = req.Write(rt.conn)
		if err != nil {
			return
		}
		// Okay to use and discard buffered reader here, because
		// TLS server will not speak until spoken to.
		br := bufio.NewReader(rt.conn)
		res, err = http.ReadResponse(br, req)
	}()
	select {
	case <-ctx.Done():
		rt.conn.Close()
		<-readDone
		return nil, ctx.Err()
	case <-readDone:
		// res or err now set
		return res, err
	}
}

// adapted from: https://pkg.go.dev/github.com/golang/gddo/httputil/header#ParseList
func parseList(s string) []string {
	var result []string
	begin := 0
	end := 0
	escape := false
	quote := false
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case escape:
			escape = false
			end = i + 1
		case quote:
			switch b {
			case '\\':
				escape = true
			case '"':
				quote = false
			}
			end = i + 1
		case b == '"':
			quote = true
			end = i + 1
		case b == ' ' || b == '\t':
			if begin == end {
				begin = i + 1
				end = begin
			}
		case b == ',':
			if begin < end {
				result = append(result, s[begin:end])
			}
			begin = i + 1
			end = begin
		default:
			end = i + 1
		}
	}
	if begin < end {
		result = append(result, s[begin:end])
	}
	return result
}

func getMD5(data ...string) string {
	h := md5.Sum([]byte(strings.Join(data, ":")))
	return hex.EncodeToString(h[:])
}

func getNonce() string {
	var buf [15]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		panic("error reading random bytes: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf[:])
}
