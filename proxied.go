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

	"github.com/dchest/uniuri"
)

func NewProxiedTransport(proxy *url.URL) http.RoundTripper {
	if proxy == nil || proxy.User == nil || (proxy.Scheme != "http" && proxy.Scheme != "https") {
		clone := http.DefaultTransport.(*http.Transport).Clone()
		clone.Proxy = http.ProxyURL(proxy)
		return clone
	}

	var tr transport

	noAuth := *proxy
	noAuth.User = nil

	tr.proxy = proxy

	tr.transport = http.DefaultTransport.(*http.Transport).Clone()
	tr.transport.Proxy = http.ProxyURL(&noAuth)

	tr.tlsTransport = http.DefaultTransport.(*http.Transport).Clone()
	tr.tlsTransport.Proxy = nil
	tr.wrapDialContext()

	return &tr
}

type transport struct {
	proxy        *url.URL
	transport    *http.Transport
	tlsTransport *http.Transport

	auth struct {
		mx    sync.Mutex
		typ   string
		realm string
		qop   string
		nonce string
		nc    int
	}
}

func (tr *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		return tr.tlsTransport.RoundTrip(req)
	}

	if auth := tr.authorize(req, ""); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}

	res, err := tr.transport.RoundTrip(req)
	if res != nil && res.StatusCode == http.StatusProxyAuthRequired {
		err = res.Body.Close()
		if err != nil {
			return nil, err
		}

		if auth := tr.authorize(req, res.Header.Get("Proxy-Authenticate")); auth != "" {
			req.Header.Set("Proxy-Authorization", auth)
			res, err = tr.transport.RoundTrip(req)
			if res != nil && res.StatusCode == http.StatusProxyAuthRequired {
				return nil, getStatusError(res.Status)
			}
		}
	}
	return res, err
}

func (tr *transport) wrapDialContext() {
	// store the default DialContext
	dialContext := tr.tlsTransport.DialContext

	// and wrap it
	tr.tlsTransport.DialContext = func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
		conn, err = dialContext(ctx, network, tr.proxy.Host)
		if err != nil {
			return nil, err
		}
		defer func() {
			if err != nil {
				conn.Close()
			}
		}()

		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}

		if auth := tr.authorize(req, ""); auth != "" {
			req.Header.Set("Proxy-Authorization", auth)
		}

		res, err := makeReq(ctx, conn, req)
		if res != nil && res.StatusCode == http.StatusProxyAuthRequired {
			err = res.Body.Close()
			if err != nil {
				return
			}

			if auth := tr.authorize(req, res.Header.Get("Proxy-Authenticate")); auth != "" {
				req.Header.Set("Proxy-Authorization", auth)
				res, err = makeReq(ctx, conn, req)
			}
		}
		if res != nil && res.StatusCode != http.StatusOK {
			err = getStatusError(res.Status)
		}
		return
	}
}

// adapted from: https://pkg.go.dev/net/http#Transport
func makeReq(ctx context.Context, conn net.Conn, connectReq *http.Request) (resp *http.Response, err error) {
	// If there's no done channel (no deadline or cancellation
	// from the caller possible), at least set some (long)
	// timeout here. This will make sure we don't block forever
	// and leak a goroutine if the connection stops replying
	// after the TCP connect.
	connectCtx := ctx
	if ctx.Done() == nil {
		newCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
		defer cancel()
		connectCtx = newCtx
	}

	didReadResponse := make(chan struct{}) // closed after CONNECT write+read is done or fails
	// Write the CONNECT request & read the response.
	go func() {
		defer close(didReadResponse)
		err = connectReq.Write(conn)
		if err != nil {
			return
		}
		// Okay to use and discard buffered reader here, because
		// TLS server will not speak until spoken to.
		br := bufio.NewReader(conn)
		resp, err = http.ReadResponse(br, connectReq)
	}()
	select {
	case <-connectCtx.Done():
		conn.Close()
		<-didReadResponse
		return nil, connectCtx.Err()
	case <-didReadResponse:
		// resp or err now set
	}
	if err != nil {
		conn.Close()
	}
	return
}

func (tr *transport) authorize(req *http.Request, authenticate string) string {
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

		switch s[0] {
		case "Basic":
			tr.auth.typ = "Basic"

		case "Digest":
			tr.auth.typ = "Digest"

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
				case "qop":
					tr.auth.qop = s[1]
				case "nonce":
					tr.auth.nonce = s[1]
				}
			}
		}
	}

	// we don't have a saved authentication type, but are secure, so try Basic
	if tr.auth.typ == "" && tr.proxy.Scheme == "https" {
		tr.auth.typ = "Basic"
	}

	switch tr.auth.typ {
	case "Basic":
		auth := username + ":" + password
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))

	case "Digest":
		tr.auth.nc += 1
		cnonce := uniuri.New()
		nc := fmt.Sprintf("%08x", tr.auth.nc)
		ha1 := getMD5(username, tr.auth.realm, password)
		ha2 := getMD5(req.Method, req.URL.String())
		response := getMD5(ha1, tr.auth.nonce, nc, cnonce, tr.auth.qop, ha2)
		return fmt.Sprintf(
			`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"`,
			username, tr.auth.realm, tr.auth.nonce, req.URL, tr.auth.qop, nc, cnonce, response)
	}

	return ""
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

func getStatusError(status string) error {
	f := strings.SplitN(status, " ", 2)
	if len(f) < 2 {
		return errors.New("unknown status code")
	}
	return errors.New(f[1])
}
