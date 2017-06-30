package metrics

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	next := m.next
	host, err := host(r)
	if err != nil {
		host = "-"
	}
	start := time.Now()

	// Record response to get status code and size of the reply.
	rw := httpserver.NewResponseRecorder(w)
	status, err := next.ServeHTTP(rw, r)

	// Transparently capture the status code so as to not side effect other plugins
	stat := status
	if err != nil && status == 0 {
		// Some middlewares set the status to 0, but return an non nil error: map these to status 500
		stat = 500
	} else if status == 0 {
		// 'proxy' returns a status code of 0, but the actual status is available on rw.
		// Note that if 'proxy' encounters an error, it returns the appropriate status code (such as 502)
		// from ServeHTTP and is captured above with 'stat := status'.
		stat = rw.Status()
	}

	fam := "1"
	ip := net.ParseIP(r.RemoteAddr)
	if ip != nil && ip.To4() == nil {
		fam = "2"
	}
	proto := strconv.Itoa(r.ProtoMajor)
	proto = proto + "." + strconv.Itoa(r.ProtoMinor)

	requestCount.WithLabelValues(host, fam, proto).Inc()
	requestDuration.WithLabelValues(host, fam, proto).Observe(float64(time.Since(start)) / float64(time.Second))
	responseSize.WithLabelValues(host).Observe(float64(rw.Size()))
	responseStatus.WithLabelValues(host, strconv.Itoa(stat)).Inc()

	return status, err
}

func host(r *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		if !strings.Contains(r.Host, ":") {
			return strings.ToLower(r.Host), nil
		}
		return "", err
	}
	return strings.ToLower(host), nil
}
