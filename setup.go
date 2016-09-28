package metrics

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func init() {
	caddy.RegisterPlugin("prometheus", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

const (
	path = "/metrics"
	addr = "localhost:9180"
)

var once sync.Once

// Metrics holds the prometheus configuration. The metrics' path is fixed to be /metrics
type Metrics struct {
	next httpserver.Handler
	addr string // where to we listen
	// subsystem?
	once sync.Once
}

func (m *Metrics) start() error {
	m.once.Do(func() {
		define("")

		prometheus.MustRegister(requestCount)
		prometheus.MustRegister(requestDuration)
		prometheus.MustRegister(responseSize)
		prometheus.MustRegister(responseStatus)

		http.Handle(path, promhttp.Handler())
		go func() {
			fmt.Errorf("%s", http.ListenAndServe(m.addr, nil))
		}()
	})
	return nil
}

func setup(c *caddy.Controller) error {
	metrics, err := parse(c)
	if err != nil {
		return err
	}
	if metrics.addr == "" {
		metrics.addr = addr
	}
	once.Do(func() {
		c.OnStartup(metrics.start)
	})

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		metrics.next = next
		return metrics
	})
	return nil
}

// prometheus {
//	address localhost:9180
// }
// Or just: prometheus localhost:9180
func parse(c *caddy.Controller) (*Metrics, error) {
	var (
		metrics *Metrics
		err     error
	)

	for c.Next() {
		if metrics != nil {
			return nil, c.Err("prometheus: can only have one metrics module per server")
		}
		metrics = &Metrics{}
		args := c.RemainingArgs()

		switch len(args) {
		case 0:
		case 1:
			metrics.addr = args[0]
		default:
			return nil, c.ArgErr()
		}
		for c.NextBlock() {
			switch c.Val() {
			case "address":
				args = c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				metrics.addr = args[0]
			default:
				return nil, c.Errf("prometheus: unknown item: %s", c.Val())
			}

		}
	}
	return metrics, err
}
