package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cello-proj/cello/internal/types"
	"github.com/cello-proj/cello/service/internal/credentials"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-hclog"
	vault "github.com/hashicorp/vault/api"
)

const TestRole = "testRole"

var errTest = fmt.Errorf("error")

func TestVaultHealthCheck(t *testing.T) {
	tests := []struct {
		name                  string
		endpoint              string // Used to cause a connection error.
		vaultStatusCode       int
		writeBadContentLength bool // Used to create response body error.
		errResult             bool
	}{
		{
			name:            "good_vault_200",
			vaultStatusCode: http.StatusOK,
		},
		{
			name:            "good_vault_429",
			vaultStatusCode: http.StatusTooManyRequests,
		},
		{
			// We want successful health check in this vault error scenario.
			name:                  "error_vault_read_response",
			vaultStatusCode:       http.StatusOK,
			writeBadContentLength: true,
		},
		{
			name:      "error_vault_connection",
			endpoint:  string('\f'),
			errResult: true,
		},
		{
			name:            "error_vault_unhealthy_status_code",
			vaultStatusCode: http.StatusInternalServerError,
			errResult:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantURL := "/v1/sys/health"

			vaultSvc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != wantURL {
					http.NotFound(w, r)
				}

				if r.Method != http.MethodGet {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}

				if tt.writeBadContentLength {
					w.Header().Set("Content-Length", "1")
				}

				w.WriteHeader(tt.vaultStatusCode)
			}))
			defer vaultSvc.Close()

			vaultEndpoint := vaultSvc.URL
			if tt.endpoint != "" {
				vaultEndpoint = tt.endpoint
			}

			v := VaultProvider{
				vaultAddr: vaultEndpoint,
			}

			_, err := v.HealthCheck()
			if err != nil {
				if !tt.errResult {
					t.Errorf("\ndid not expect error, got: %v", err)
				}
			} else {
				if tt.errResult {
					t.Errorf("\nexpected error")
				}
			}
		})
	}
}

func TestVaultCreateProject(t *testing.T) {
	tests := []struct {
		name                   string
		admin                  bool
		expectedRole           string
		expectedSecret         string
		expectedSecretAccessor string
		vaultErr               error
		errResult              bool
	}{
		{
			name:                   "create project success",
			admin:                  true,
			expectedSecret:         "test-secret",
			expectedSecretAccessor: "test-secret-accessor",
			expectedRole:           "test-role",
		},
		{
			name:      "create project admin error",
			admin:     false,
			errResult: true,
		},
		{
			name:      "create project error",
			admin:     true,
			vaultErr:  errTest,
			errResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := TestRole
			if tt.admin {
				role = authorizationKeyAdmin
			}

			v := VaultProvider{
				roleID: role,
				vaultSvcFn: mockVaultSvc(vaultSvc{
					roleID: role,
					vaultLogicalSvc: &mockVaultLogical{err: tt.vaultErr, data: map[string]interface{}{
						"secret_id":          tt.expectedSecret,
						"secret_id_accessor": tt.expectedSecretAccessor,
						"role_id":            tt.expectedRole,
						"creation_time":      "2022-07-01T14:56:10.341066-07:00",
						"expiration_time":    "2023-07-01T14:56:10.341066-07:00",
					}},
					vaultSysSvc: &mockVaultSys{},
				}),
			}

			resp, err := v.CreateProject(credentials.CreateProjectInput{
				ProjectName: "testProject",
			})

			if err != nil {
				if !tt.errResult {
					t.Errorf("\ndid not expect error, got: %v", err)
				}
			} else {
				token := resp.Token
				if tt.errResult {
					t.Errorf("\nexpected error")
				}
				if !cmp.Equal(token.RoleID, tt.expectedRole) {
					t.Errorf("\nwant: %v\n got: %v", tt.expectedRole, token.RoleID)
				}
				if !cmp.Equal(token.Secret, tt.expectedSecret) {
					t.Errorf("\nwant: %v\n got: %v", tt.expectedSecret, token.Secret)
				}
			}
		})
	}
}

func TestVaultCreateTarget(t *testing.T) {
	tests := []struct {
		name      string
		admin     bool
		vaultErr  error
		errResult bool
	}{
		{
			name:  "create target success",
			admin: true,
		},
		{
			name:      "create target admin error",
			admin:     false,
			errResult: true,
		},
		{
			name:      "create target error",
			admin:     true,
			vaultErr:  errTest,
			errResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := TestRole
			if tt.admin {
				role = authorizationKeyAdmin
			}

			v := VaultProvider{
				logger: hclog.NewNullLogger(),
				roleID: role,
				vaultSvcFn: mockVaultSvc(vaultSvc{
					roleID:          role,
					vaultLogicalSvc: &mockVaultLogical{err: tt.vaultErr},
				}),
			}

			_, err := v.CreateTarget(credentials.CreateTargetInput{
				ProjectName: "testProject",
				Target:      types.Target{},
			})

			if err != nil {
				if !tt.errResult {
					t.Errorf("\ndid not expect error, got: %v", err)
				}
			} else {
				if tt.errResult {
					t.Errorf("\nexpected error")
				}
			}
		})
	}
}

func TestVaultDeleteProject(t *testing.T) {
	tests := []struct {
		name           string
		admin          bool
		vaultErr       error
		vaultPolicyErr error
		errResult      bool
	}{
		{
			name:  "delete project success",
			admin: true,
		},
		{
			name:      "delete project admin error",
			admin:     false,
			errResult: true,
		},
		{
			name:      "delete project error",
			admin:     true,
			vaultErr:  errTest,
			errResult: true,
		},
		{
			name:           "delete project policy error",
			admin:          true,
			vaultPolicyErr: errTest,
			errResult:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := TestRole
			if tt.admin {
				role = authorizationKeyAdmin
			}

			v := VaultProvider{
				roleID: role,
				vaultSvcFn: mockVaultSvc(vaultSvc{
					roleID:          role,
					vaultLogicalSvc: &mockVaultLogical{err: tt.vaultErr},
					vaultSysSvc:     &mockVaultSys{err: tt.vaultPolicyErr},
				}),
			}

			// TODO check the response?
			_, err := v.DeleteProject(credentials.DeleteProjectInput{
				ProjectName: "testProject",
			})
			if err != nil {
				if !tt.errResult {
					t.Errorf("\ndid not expect error, got: %v", err)
				}
			} else {
				if tt.errResult {
					t.Errorf("\nexpected error")
				}
			}
		})
	}
}

func TestVaultDeleteTarget(t *testing.T) {
	tests := []struct {
		name      string
		admin     bool
		vaultErr  error
		errResult bool
	}{
		{
			name:  "delete target success",
			admin: true,
		},
		{
			name:      "delete target admin error",
			admin:     false,
			errResult: true,
		},
		{
			name:      "delete target error",
			admin:     true,
			vaultErr:  errTest,
			errResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := TestRole
			if tt.admin {
				role = authorizationKeyAdmin
			}

			v := VaultProvider{
				roleID: role,
				vaultSvcFn: mockVaultSvc(vaultSvc{
					roleID:          role,
					vaultLogicalSvc: &mockVaultLogical{err: tt.vaultErr},
				}),
			}

			_, err := v.DeleteTarget(credentials.DeleteTargetInput{
				ProjectName: "testProject",
				TargetName:  "testTarget",
			})
			if err != nil {
				if !tt.errResult {
					t.Errorf("\ndid not expect error, got: %v", err)
				}
			} else {
				if tt.errResult {
					t.Errorf("\nexpected error")
				}
			}
		})
	}
}

func TestGetProject(t *testing.T) {
	tests := []struct {
		name      string
		vaultErr  error
		errResult bool
	}{
		{
			name: "get project success",
		},
		{
			name:      "get project error",
			vaultErr:  errTest,
			errResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := TestRole

			v := VaultProvider{
				roleID: role,
				vaultSvcFn: mockVaultSvc(vaultSvc{
					roleID:          role,
					vaultLogicalSvc: &mockVaultLogical{err: tt.vaultErr},
					vaultSysSvc:     &mockVaultSys{},
				}),
			}

			// TODO should this test the result?
			_, err := v.GetProject(credentials.GetProjectInput{
				ProjectName: "testProject",
			})
			if err != nil {
				if !tt.errResult {
					t.Errorf("\ndid not expect error, got: %v", err)
				}
			} else {
				if tt.errResult {
					t.Errorf("\nexpected error")
				}
			}
		})
	}
}

func TestGetTarget(t *testing.T) {
	tests := []struct {
		name      string
		admin     bool
		vaultErr  error
		errResult bool
	}{
		{
			name:  "get target success",
			admin: true,
		},
		// TODO remove/update depending on if this should require admin or not.
		// {
		// 	name:      "get target admin error",
		// 	admin:     false,
		// 	errResult: true,
		// },
		{
			name:      "get target error",
			admin:     true,
			vaultErr:  errTest,
			errResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := TestRole
			if tt.admin {
				role = authorizationKeyAdmin
			}

			v := VaultProvider{
				roleID: role,
				vaultSvcFn: mockVaultSvc(vaultSvc{
					roleID: role,
					vaultLogicalSvc: &mockVaultLogical{err: tt.vaultErr, data: map[string]interface{}{
						"role_arns":       []interface{}{"test-role-arn"},
						"policy_arns":     []interface{}{"test-policy-arn"},
						"policy_document": `{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Action": "s3:ListBuckets", "Resource": "*" } ] }`,
						"credential_type": "test-cred-type",
					}},
					vaultSysSvc: &mockVaultSys{},
				}),
			}

			// TODO should this test the result?
			_, err := v.GetTarget(credentials.GetTargetInput{
				ProjectName: "testProject",
				TargetName:  "testTarget",
			})
			if err != nil {
				if !tt.errResult {
					t.Errorf("\ndid not expect error, got: %v", err)
				}
			} else {
				if tt.errResult {
					t.Errorf("\nexpected error")
				}
			}
		})
	}
}

func TestVaultGetToken(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		admin     bool
		vaultErr  error
		errResult bool
	}{
		{
			name:  "get token success",
			token: "secretToken",
		},
		{
			name:      "get token admin error",
			admin:     true,
			errResult: true,
		},
		{
			name:      "get token error",
			vaultErr:  errTest,
			errResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := TestRole
			if tt.admin {
				role = authorizationKeyAdmin
			}

			v := VaultProvider{
				roleID: role,
				vaultSvcFn: mockVaultSvc(vaultSvc{
					roleID: role,
					vaultLogicalSvc: &mockVaultLogical{
						err:   tt.vaultErr,
						token: tt.token,
					},
				}),
			}

			resp, err := v.GetToken(credentials.GetTokenInput{})
			if err != nil {
				if !tt.errResult {
					t.Errorf("\ndid not expect error, got: %v", err)
				}
			} else {
				if tt.errResult {
					t.Errorf("\nexpected error")
				}
				if !cmp.Equal(resp.Token, tt.token) {
					t.Errorf("\nwant: %v\n got: %v", tt.token, resp)
				}
			}
		})
	}
}

// TODO need 'Vault' in all of these?
func TestVaultListTargets(t *testing.T) {
	tests := []struct {
		name            string
		admin           bool
		want            credentials.ListTargetsOutput
		expectedTargets []string
		vaultErr        error
		errResult       bool
	}{
		{
			name:  "list target success",
			admin: true,
			want: credentials.ListTargetsOutput{
				Targets: []string{"target1", "target2"},
			},
		},
		{
			name:      "list target admin error",
			admin:     false,
			errResult: true,
		},
		{
			name:      "list target error",
			admin:     true,
			vaultErr:  errTest,
			errResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := TestRole
			if tt.admin {
				role = authorizationKeyAdmin
			}

			var testTargets []interface{}
			for _, i := range tt.want.Targets {
				testTargets = append(testTargets, fmt.Sprintf("argo-cloudops-projects-test-target-%s", i))
			}

			v := VaultProvider{
				roleID: role,
				vaultSvcFn: mockVaultSvc(vaultSvc{
					roleID: role,
					vaultLogicalSvc: &mockVaultLogical{
						err: tt.vaultErr,
						data: map[string]interface{}{
							"keys": testTargets,
						},
					},
				}),
			}

			resp, err := v.ListTargets(credentials.ListTargetsInput{
				ProjectName: "test",
			})
			if err != nil {
				if !tt.errResult {
					t.Errorf("\ndid not expect error, got: %v", err)
				}
			} else {
				if tt.errResult {
					t.Errorf("\nexpected error")
				}
				if !cmp.Equal(resp, tt.want) {
					t.Errorf("\nwant: %v\n got: %v", tt.want, resp)
				}
			}
		})
	}
}

func TestVaultProjectExists(t *testing.T) {
	tests := []struct {
		name      string
		exists    bool
		vaultErr  error
		expectErr bool
	}{
		{
			name:   "get project success",
			exists: true,
		},
		{
			name:      "get project not found",
			exists:    false,
			vaultErr:  errNotFound,
			expectErr: false,
		},
		{
			name:      "vault error",
			exists:    false,
			vaultErr:  errTest,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := VaultProvider{
				vaultSvcFn: mockVaultSvc(vaultSvc{
					vaultLogicalSvc: &mockVaultLogical{err: tt.vaultErr},
				}),
			}

			resp, err := v.ProjectExists(credentials.ProjectExistsInput{
				ProjectName: "testProject",
			})
			if err != nil {
				if !tt.expectErr {
					t.Errorf("\ndid not expect error, got: %v", err)
				}
			} else {
				if tt.expectErr {
					t.Errorf("\nexpected error")
				}

				if !cmp.Equal(resp.Exists, tt.exists) {
					t.Errorf("\nwant: %v\n got: %v", tt.exists, resp.Exists)
				}
			}
		})
	}
}

func TestVaultProjectTokenExists(t *testing.T) {
	tests := []struct {
		name          string
		admin         bool
		want          credentials.ProjectTokenExistsOutput
		mockVaultData map[string]interface{}
		vaultErr      error
		errResult     bool
	}{
		{
			name:  "exists",
			admin: true,
			want: credentials.ProjectTokenExistsOutput{
				Exists: true,
			},
			mockVaultData: map[string]interface{}{
				"creation_time":      "2022-06-21T14:43:16.172896-07:00",
				"expiration_time":    "2023-06-21T14:43:16.172896-07:00",
				"secret_id_accessor": "secret-id-accessor",
			},
		},
		{
			name:  "does not exist",
			admin: true,
			want: credentials.ProjectTokenExistsOutput{
				Exists: false,
			},
			vaultErr:      fmt.Errorf("failed to find accessor entry for secret_id_accessor"),
			errResult:     false,
			mockVaultData: map[string]interface{}{},
		},
		{
			name:          "error",
			admin:         true,
			vaultErr:      errTest,
			errResult:     true,
			mockVaultData: map[string]interface{}{},
		},
		{
			name:      "not admin",
			admin:     false,
			errResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := TestRole
			if tt.admin {
				role = authorizationKeyAdmin
			}
			v := VaultProvider{
				roleID: role,
				vaultSvcFn: mockVaultSvc(vaultSvc{
					roleID: role,
					vaultLogicalSvc: &mockVaultLogical{
						data: tt.mockVaultData,
						err:  tt.vaultErr,
					},
				}),
			}

			resp, err := v.ProjectTokenExists(credentials.ProjectTokenExistsInput{
				ProjectName: "testProject",
				TokenID:     "testToken",
			})
			if err != nil {
				if !tt.errResult {
					t.Errorf("\ndid not expect error, got: %v", err)
				}
			} else {
				if tt.errResult {
					t.Errorf("\nexpected error")
				}
				if !cmp.Equal(resp, tt.want) {
					t.Errorf("\nwant: %v\n got: %v", tt.want, resp)
				}
			}
		})
	}
}

func mockVaultSvc(vSvc vaultSvc) func(auth credentials.Authorization, h http.Header) (vaultSvc, error) {
	return func(auth credentials.Authorization, h http.Header) (vaultSvc, error) {
		return vSvc, nil
	}
}

type mockVaultLogical struct {
	vault.Logical
	data  map[string]interface{}
	token string
	err   error
}

func (m mockVaultLogical) Read(path string) (*vault.Secret, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &vault.Secret{Data: m.data}, nil
}

func (m mockVaultLogical) List(path string) (*vault.Secret, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &vault.Secret{Data: m.data}, nil
}

func (m mockVaultLogical) Write(path string, data map[string]interface{}) (*vault.Secret, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &vault.Secret{Data: m.data, Auth: &vault.SecretAuth{ClientToken: m.token}}, nil
}

func (m mockVaultLogical) Delete(path string) (*vault.Secret, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &vault.Secret{}, nil
}

type mockVaultSys struct {
	vault.Sys
	err error
}

func (m mockVaultSys) PutPolicy(name, rules string) error {
	return m.err
}

func (m mockVaultSys) DeletePolicy(name string) error {
	return m.err
}
