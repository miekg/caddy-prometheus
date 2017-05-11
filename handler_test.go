package metrics

import (
	"net/http"
	"sync"
	"testing"

	"net/http/httptest"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func TestMetrics_ServeHTTP(t *testing.T) {
	successRequest, err := http.NewRequest("GET", "http://test.com/success", nil)
	errorRequest, err := http.NewRequest("GET", "http://test.com/error", nil)
	proxyRequest, err := http.NewRequest("GET", "http://test.com/proxy", nil)

	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		next httpserver.Handler
		addr string
		once sync.Once
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    int
		wantErr bool
	}{
		{
			name: "200 handler response",
			fields: fields{
				next: testHandler{},
				addr: "success",
				once: sync.Once{},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: successRequest,
			},
			want:    200,
			wantErr: false,
		},
		{
			name: "500 handler response",
			fields: fields{
				next: testHandler{},
				addr: "success",
				once: sync.Once{},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: errorRequest,
			},
			want:    500,
			wantErr: false,
		},
		{
			name: "proxy handler response",
			fields: fields{
				next: testHandler{},
				addr: "success",
				once: sync.Once{},
			},
			args: args{
				w: httptest.NewRecorder(),
				r: proxyRequest,
			},
			// httpserver.ResponseRecord defaults to a status code of 200
			want:    200,
			wantErr: false,
		},
	}

	m := &Metrics{
		next: tests[0].fields.next,
		addr: tests[0].fields.addr,
		once: tests[0].fields.once,
	}
	m.start()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.next = tt.fields.next
			m.addr = tt.fields.addr
			got, err := m.ServeHTTP(tt.args.w, tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("Metrics.ServeHTTP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Metrics.ServeHTTP() = %v, want %v", got, tt.want)
			}
		})
	}
}

type testHandler struct{}

func (h testHandler) ServeHTTP(_ http.ResponseWriter, r *http.Request) (int, error) {
	var status int

	switch r.URL.Path {
	case "/success":
		status = 200
	case "/error":
		status = 500
	}

	return status, nil
}
