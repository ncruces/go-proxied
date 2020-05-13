package proxied

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
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

func TestNewProxiedTransport(t *testing.T) {
	res, err := client.Get("http://1.1.1.1/cdn-cgi/trace")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatal(http.StatusText(res.StatusCode))
	}

	_, err = io.Copy(os.Stdout, res.Body)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewProxiedTransportTLS(t *testing.T) {
	res, err := client.Get("https://1.1.1.1/cdn-cgi/trace")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatal(http.StatusText(res.StatusCode))
	}

	_, err = io.Copy(os.Stdout, res.Body)
	if err != nil {
		t.Fatal(err)
	}
}
