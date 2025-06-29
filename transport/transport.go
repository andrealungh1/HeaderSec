// transport/transport.go
package transport

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)


func New(timeout time.Duration, insecure bool, proxy string, follow bool, maxRed int) (*http.Client, error) {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
	}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} 
	}
	if proxy != "" {
		pu, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(pu)
	}

	c := &http.Client{Timeout: timeout, Transport: tr}
	if !follow {
		c.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		c.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxRed {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}
	return c, nil
}
