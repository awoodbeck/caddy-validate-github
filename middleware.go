package validate

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

var (
	_ caddy.Module                = (*Middleware)(nil)
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("validate_github", parseCaddyfileHandler)
}

type Middleware struct {
	Secret string `json:"secret,omitempty"`

	logger *zap.SugaredLogger
	secret []byte
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.validate_github",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision implements the caddy.Provisioner interface.
func (m *Middleware) Provision(ctx caddy.Context) error {
	if m.logger == nil {
		m.logger = ctx.Logger(m).Sugar()
	}

	return nil
}

// ServeHTTP implements the caddy.Handler interface.
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request,
	next caddyhttp.Handler) error {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		m.logger.Errorf("reading request body: %v", err)
		http.Error(w, "invalid signature", http.StatusForbidden)
		return nil
	}
	_ = r.Body.Close()

	if len(b) == 0 {
		m.logger.Debug("cannot validate an empty request body")
		http.Error(w, "invalid signature", http.StatusForbidden)
		return nil
	}

	s := strings.TrimPrefix(r.Header.Get("X-Hub-Signature-256"), "sha256=")
	if s == "" {
		m.logger.Debug("missing X-Hub-Signature-256 header in request")
		http.Error(w, "invalid signature", http.StatusForbidden)
		return nil
	}
	sig, err := hex.DecodeString(s)
	if err != nil {
		m.logger.Debugf("error hex-decoding signature '%s': %v", s, err)
		http.Error(w, "invalid signature", http.StatusForbidden)
		return nil
	}

	mac := hmac.New(sha256.New, m.secret)
	mac.Write(b)
	if sum := mac.Sum(nil); !hmac.Equal(sum, sig) { // constant time comparison
		m.logger.Debugf("signature: expected '%x'; received '%s'", sum, s)
		http.Error(w, "invalid signature", http.StatusForbidden)
		return nil
	}

	m.logger.Debugf("successful webhook invocation from %s", r.RemoteAddr)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(b))

	return next.ServeHTTP(w, r)
}

func (m *Middleware) Validate() error {
	if m.Secret == "" {
		return fmt.Errorf("empty secret")
	}

	m.secret = []byte(m.Secret)

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//     validate_github <secret>
//
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&m.Secret) {
			return d.ArgErr()
		}
		if d.NextArg() {
			return d.ArgErr()
		}
	}

	return nil
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler,
	error) {
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}

	return m, nil
}
