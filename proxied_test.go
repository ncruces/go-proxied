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
