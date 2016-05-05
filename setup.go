package metrics

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	path = "/metrics"
	addr = ":9180"
)

var once sync.Once

// Metrics holds the prometheus configuration. The metrics' path is fixed to be /metrics
type Metrics struct {
	next middleware.Handler
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

		http.Handle(path, prometheus.Handler())
		go func() {
			fmt.Errorf("%s", http.ListenAndServe(m.addr, nil))
		}()
	})
	return nil
}

func Setup(c *setup.Controller) (middleware.Middleware, error) {
	metrics, err := parse(c)
	if err != nil {
		return nil, err
	}
	if metrics.addr == "" {
		metrics.addr = addr
	}
	once.Do(func() {
		c.Startup = append(c.Startup, metrics.start)
	})

	return func(next middleware.Handler) middleware.Handler {
		metrics.next = next
		return metrics
	}, nil
}

// prometheus {
//	address localhost:9180
// }
// Or just: prometheus localhost:9180
func parse(c *setup.Controller) (*Metrics, error) {
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
