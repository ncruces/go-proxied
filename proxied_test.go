package proxied

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

var client http.Client

func TestMain(m *testing.M) {
	env := os.Getenv("HTTP_PROXY")
	if env == "" {
		log.Fatal("Please set HTTP_PROXY")
	}

	proxy, err := url.Parse(env)
	if err != nil {
		proxy, err = url.Parse("http://" + env)
	}
	if err != nil {
		log.Fatal(err)
	}

	client = http.Client{Transport: NewProxiedTransport(proxy)}

	os.Exit(m.Run())
}

func TestProxiedTransport(t *testing.T) {
	var urls = []string{
		"http://1.1.1.1/cdn-cgi/trace",
		"http://cloudflare-dns.com/cdn-cgi/trace",
		"http://[2606:4700:4700::1111]/cdn-cgi/trace",
		"https://1.1.1.1/cdn-cgi/trace",
		"https://cloudflare-dns.com/cdn-cgi/trace",
		"https://[2606:4700:4700::1111]/cdn-cgi/trace",
	}
	for _, url := range urls {
		t.Run(url, func(t *testing.T) {
			res, err := client.Get(url)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()

			if res.StatusCode != http.StatusOK {
				t.Fatal(http.StatusText(res.StatusCode))
			}

			var buf strings.Builder
			if _, err = io.Copy(&buf, res.Body); err != nil {
				t.Fatal(err)
			} else {
				t.Log(buf.String())
			}
		})
	}
}

func Test_quote(t *testing.T) {
	tests := map[string]struct {
		s    string
		want string
	}{
		"simple":  {s: `abc`, want: `"abc"`},
		"quotes":  {s: `"abc"`, want: `"\"abc\""`},
		"escapes": {s: `\abc\`, want: `"\\abc\\"`},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := quote(tt.s); got != tt.want {
				t.Errorf("quote(%v) = %v, want %v", tt.s, got, tt.want)
			} else if got := unquote(got); got != tt.s {
				t.Errorf("unquote(quote(%v) = %v, want %v", tt.s, got, tt.s)
			}
		})
	}
}

func Test_unquote(t *testing.T) {
	tests := map[string]struct {
		s    string
		want string
	}{
		"simple":       {s: `abc`, want: `abc`},
		"quoted":       {s: `"abc"`, want: `abc`},
		"escaped":      {s: `"\"abc\""`, want: `"abc"`},
		"stray quote":  {s: `"abc""`, want: `"abc""`},
		"stray escape": {s: `"abc\"`, want: `"abc\"`},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := unquote(tt.s); got != tt.want {
				t.Errorf("unquote(%v) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}
