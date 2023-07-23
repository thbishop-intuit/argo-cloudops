package credentials

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const TestRole = "testRole"

var errTest = fmt.Errorf("error")

func TestValidateAuthorizedAdmin(t *testing.T) {
	tests := []struct {
		name        string
		admin       bool
		validSecret bool
		expectErr   bool
	}{
		{
			name:        "is authorized admin",
			admin:       true,
			validSecret: true,
			expectErr:   false,
		},
		{
			name:        "isn't admin, with valid secret",
			admin:       false,
			validSecret: true,
			expectErr:   true,
		},
		{
			name:        "is admin, with invalid secret",
			admin:       true,
			validSecret: false,
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "test"
			if tt.admin {
				key = authorizationKeyAdmin
			}
			secret := "invalidSecret"
			if tt.validSecret {
				secret = "validSecret"
			}
			a := Authorization{Provider: "vault", Key: key, Secret: secret}
			err := a.Validate(a.ValidateAuthorizedAdmin("validSecret"))
			if err != nil != tt.expectErr {
				t.Errorf("\nwant error: %v\n got error: %v", tt.expectErr, err != nil)
			}
		})
	}
}

func TestNewAuthorization(t *testing.T) {
	tests := []struct {
		name         string
		header       string
		expectedAuth *Authorization
		expectErr    bool
	}{
		{
			name:         "valid authorization header",
			header:       "vault:testkey:testsecret",
			expectedAuth: &Authorization{"vault", "testkey", "testsecret"},
			expectErr:    false,
		},
		{
			name:      "invalid authorization header",
			header:    "vault:testbad",
			expectErr: true,
		},
		{
			name:      "authorization header empty",
			header:    "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := NewAuthorization(tt.header)
			if err != nil != tt.expectErr {
				t.Errorf("\nwant error: %v\n got error: %v", tt.expectErr, err != nil)
			}
			if !cmp.Equal(a, tt.expectedAuth) {
				t.Errorf("\nwant auth: %v\n got: %v", tt.expectedAuth, a)
			}
		})
	}
}
