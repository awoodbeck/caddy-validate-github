package validate

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap/zaptest"
)

func TestValidateGitHub(t *testing.T) {
	testCases := []struct {
		Body         []byte
		ClientSecret string
		Secret       string
		Validates    bool
		ResponseCode int
	}{
		{ // missing shared secret
			Validates: false,
		},
		{ // valid request
			Body:         []byte("bdf3d7cdb794dd1cac43069ab8b4447327dc927c"),
			ClientSecret: "blah",
			Secret:       "blah",
			Validates:    true,
			ResponseCode: http.StatusAccepted,
		},
		{ // empty request body
			ClientSecret: "blah",
			Secret:       "blah",
			Validates:    true,
			ResponseCode: http.StatusForbidden,
		},
		{ // mismatched shared secrets
			Body:         []byte("f0a1a256f39a17d10dd0559161eba47d687f42cb"),
			ClientSecret: "foo",
			Secret:       "bar",
			Validates:    true,
			ResponseCode: http.StatusForbidden,
		},
	}

	var ctx caddy.Context
	next := caddyhttp.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusAccepted)
			return nil
		},
	)
	log := zaptest.NewLogger(t).Sugar()

	for i, tc := range testCases {
		m := Middleware{Secret: tc.Secret, logger: log}
		_ = m.Provision(ctx)

		if err := m.Validate(); tc.Validates != (err == nil) {
			t.Errorf("%d: expected validation == %t; actual validation == %t",
				i, tc.Validates, tc.Validates == !tc.Validates)
			continue
		} else if err != nil {
			continue
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(tc.Body))
		r.Header.Add("X-Hub-Signature-256", hashFromSecret(tc.ClientSecret, tc.Body))
		if err := m.ServeHTTP(w, r, next); err != nil {
			t.Errorf("%d: unexpected error: %v", i, err)
		}

		if tc.ResponseCode != w.Code {
			t.Errorf("%d: expected status code %d; actual status code %d",
				i, tc.ResponseCode, w.Code)
		}

		if w.Code == http.StatusAccepted {
			b, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Errorf("%d: %v", i, err)
				continue
			}
			_ = r.Body.Close()

			if len(b) == 0 {
				t.Errorf("%d: request body empty downstream from middleware", i)
			}
		}
	}
}

func hashFromSecret(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return fmt.Sprintf("sha256=%x", mac.Sum(nil))
}
