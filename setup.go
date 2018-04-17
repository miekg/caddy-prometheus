package metrics

import (
	"log"
	"net/http"
	"os"
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
	defaultPath = "/metrics"
	defaultAddr = "localhost:9180"
)

var once sync.Once

// BasicAuth holds basic auth credentials
type BasicAuth struct {
	username string
	password string
}

// Metrics holds the prometheus configuration.
type Metrics struct {
	next         httpserver.Handler
	addr         string // where to we listen
	useCaddyAddr bool
	hostname     string
	path         string
	basicAuth    []BasicAuth
	// subsystem?
	once sync.Once

	handler http.Handler
}

// NewMetrics -
func NewMetrics() *Metrics {
	return &Metrics{
		path:      defaultPath,
		addr:      defaultAddr,
	}
}

func (m *Metrics) start() error {
	m.once.Do(func() {
		define("")

		prometheus.MustRegister(requestCount)
		prometheus.MustRegister(requestDuration)
		prometheus.MustRegister(responseLatency)
		prometheus.MustRegister(responseSize)
		prometheus.MustRegister(responseStatus)

		if !m.useCaddyAddr {
			http.Handle(m.path, m.handler)
			go func() {
				err := http.ListenAndServe(m.addr, nil)
				if err != nil {
					log.Printf("[ERROR] Starting handler: %v", err)
				}
			}()
		}
	})
	return nil
}

func (m *Metrics) authMiddleware() http.Handler {
	// if provided credentials match, this handler will be served
	promHandler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
		ErrorHandling: promhttp.HTTPErrorOnError,
		ErrorLog:      log.New(os.Stderr, "", log.LstdFlags),
	})

	// authFunc checks if username+password match
	authFunc := func(givenUsername string, givenPassword string, requiredCred BasicAuth) bool {
		if givenUsername != requiredCred.username || givenPassword != requiredCred.password {
			return false
		}
		return true
	}

	// auth middleware starts here
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.basicAuth != nil && len(m.basicAuth) > 0 {

			// parse 'Authorization' header
			username, password, ok := r.BasicAuth()

			isAuth := false
			if ok {
				for _, cred := range m.basicAuth {
					if authFunc(username, password, cred) == false {
						continue
					}
					isAuth = true
				}
			}

			// auth failed, let's return realm
			if isAuth == false {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Restricted area\"")
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
		}

		// auth looks good, we can serve prometheus metrics safely
		promHandler.ServeHTTP(w, r)
	})
}

func setup(c *caddy.Controller) error {
	metrics, err := parse(c)
	if err != nil {
		return err
	}

	metrics.handler = metrics.authMiddleware()

	once.Do(func() {
		c.OnStartup(metrics.start)
	})

	cfg := httpserver.GetConfig(c)
	if metrics.useCaddyAddr {
		cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
			return httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				if r.URL.Path == metrics.path {
					metrics.handler.ServeHTTP(w, r)
					return 0, nil
				}
				return next.ServeHTTP(w, r)
			})
		})
	}
	cfg.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
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
		metrics = NewMetrics()
		args := c.RemainingArgs()

		switch len(args) {
		case 0:
		case 1:
			metrics.addr = args[0]
		default:
			return nil, c.ArgErr()
		}
		addrSet := false
		for c.NextBlock() {
			switch c.Val() {
			case "path":
				args = c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				metrics.path = args[0]
			case "address":
				if metrics.useCaddyAddr {
					return nil, c.Err("prometheus: address and use_caddy_addr options may not be used together")
				}
				args = c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				metrics.addr = args[0]
				addrSet = true
			case "hostname":
				args = c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				metrics.hostname = args[0]
			case "use_caddy_addr":
				if addrSet {
					return nil, c.Err("prometheus: address and use_caddy_addr options may not be used together")
				}
				metrics.useCaddyAddr = true
			case "basicauth":
				args = c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.ArgErr()
				}
				metrics.basicAuth = append(metrics.basicAuth, BasicAuth{username: args[0], password: args[1]})
			default:
				return nil, c.Errf("prometheus: unknown item: %s", c.Val())
			}
		}
	}
	return metrics, err
}
