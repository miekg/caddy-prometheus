package metrics

import (
	"testing"

	"github.com/mholt/caddy"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		expected  *Metrics
	}{
		{`prometheus`, false, &Metrics{}},
		{`prometheus foo`, false, &Metrics{addr: "foo"}},
		{`prometheus foo bar`, true, nil},
		{`prometheus {
			a b
		}`, true, nil},
		{`prometheus
			prometheus`, true, nil},
		{`prometheus {
			address
		}`, true, nil},
		{`prometheus {
			hostname
		}`, true, nil},
		{`prometheus {
			address 0.0.0.0:1234
			use_caddy_addr
		}`, true, nil},
		{`prometheus {
			use_caddy_addr
			address 0.0.0.0:1234
		}`, true, nil},
		{`prometheus {
			use_caddy_addr
		}`, false, &Metrics{useCaddyAddr: true}},
		{`prometheus {
			use_caddy_addr
			hostname example.com
		}`, false, &Metrics{useCaddyAddr: true, hostname: "example.com"}},
	}
	for i, test := range tests {
		c := caddy.NewTestController("http", test.input)
		m, err := parse(c)
		if test.expected != m && *test.expected != *m {
			t.Errorf("Test %v: Created Metrics (\n%#v\n) does not match expected (\n%#v\n)", i, m, test.expected)
		}
		if test.shouldErr && err == nil {
			t.Errorf("Test %v: Expected error but found nil", i)
		} else if !test.shouldErr && err != nil {
			t.Errorf("Test %v: Expected no error but found error: %v", i, err)
		}
	}
}
