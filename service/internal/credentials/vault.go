//go:generate moq -out ../../test/testhelpers/credsProviderMock.go -pkg testhelpers . Provider:CredsProviderMock

package credentials

import (
	"errors"
	"fmt"
	"net/http"
	"net/rpc"
	"strings"

	"github.com/cello-proj/cello/internal/responses"
	"github.com/cello-proj/cello/internal/types"
	"github.com/cello-proj/cello/internal/validations"
	"github.com/cello-proj/cello/service/internal/env"

	"github.com/hashicorp/go-plugin"
	vault "github.com/hashicorp/vault/api"
)

const (
	authorizationKeyAdmin = "admin"
)

// Provider defines the interface required by providers.
type Provider interface {
	CreateProject(string) (types.Token, error)
	CreateTarget(string, types.Target) error
	CreateToken(string) (types.Token, error)
	UpdateTarget(string, types.Target) error
	DeleteProject(string) error
	DeleteTarget(string, string) error
	GetProject(string) (responses.GetProject, error)
	GetTarget(string, string) (types.Target, error)
	GetToken() (string, error)
	DeleteProjectToken(string, string) error
	GetProjectToken(string, string) (types.ProjectToken, error)
	ListTargets(string) ([]string, error)
	ProjectExists(string) (bool, error)
	TargetExists(string, string) (bool, error)
}

type vaultLogical interface {
	Delete(path string) (*vault.Secret, error)
	List(path string) (*vault.Secret, error)
	Read(path string) (*vault.Secret, error)
	Write(path string, data map[string]interface{}) (*vault.Secret, error)
}

type vaultSys interface {
	DeletePolicy(name string) error
	PutPolicy(name, rules string) error
}

// Vault
const (
	vaultAppRolePrefix = "auth/approle/role"
	vaultProjectPrefix = "argo-cloudops-projects"
)

var (
	// ErrNotFound conveys that the item was not found.
	ErrNotFound = errors.New("item not found")
	// ErrTargetNotFound conveys that the target was not round.
	ErrTargetNotFound = errors.New("target not found")
	// ErrProjectTokenNotFound conveys that the token was not found.
	ErrProjectTokenNotFound = errors.New("project token not found")
)

type VaultProvider struct {
	roleID          string
	secretID        string
	vaultLogicalSvc vaultLogical
	vaultSysSvc     vaultSys
}

// NewVaultProvider returns a new VaultProvider
func NewVaultProvider(a Authorization, env env.Vars, h http.Header, vaultConfigFn VaultConfigFn, vaultSvcFn VaultSvcFn) (Provider, error) {
	config := vaultConfigFn(&vault.Config{Address: env.VaultAddress}, env.VaultRole, env.VaultSecret)
	svc, err := vaultSvcFn(*config, h)
	if err != nil {
		return nil, err
	}
	return &VaultProvider{
		vaultLogicalSvc: vaultLogical(svc.Logical()),
		vaultSysSvc:     vaultSys(svc.Sys()),
		roleID:          a.Key,
		secretID:        a.Secret,
	}, nil
}

type VaultConfig struct {
	config *vault.Config
	role   string
	secret string
}

type VaultConfigFn func(config *vault.Config, role, secret string) *VaultConfig

// NewVaultConfig returns a new VaultConfig.
func NewVaultConfig(config *vault.Config, role, secret string) *VaultConfig {
	return &VaultConfig{
		config: config,
		role:   role,
		secret: secret,
	}
}

type VaultSvcFn func(c VaultConfig, h http.Header) (svc *vault.Client, err error)

// NewVaultSvc returns a new vault.Client.
// TODO before open sourcing we should provide the token instead of generating it
// TODO rename to client?
func NewVaultSvc(c VaultConfig, h http.Header) (*vault.Client, error) {
	vaultSvc, err := vault.NewClient(c.config)
	if err != nil {
		return nil, err
	}

	vaultSvc.SetHeaders(h)

	options := map[string]interface{}{
		"role_id":   c.role,
		"secret_id": c.secret,
	}

	sec, err := vaultSvc.Logical().Write("auth/approle/login", options)
	if err != nil {
		return nil, err
	}

	vaultSvc.SetToken(sec.Auth.ClientToken)
	return vaultSvc, nil
}

// Authorization represents a user's authorization token.
type Authorization struct {
	Provider string `valid:"required"`
	Key      string `valid:"required"`
	Secret   string `valid:"required"`
}

func (a Authorization) Validate(optionalValidations ...func() error) error {
	v := []func() error{
		func() error {
			if a.Provider != "vault" {
				return errors.New("provider must be vault")
			}
			return nil
		},
		func() error { return validations.ValidateStruct(a) },
	}

	v = append(v, optionalValidations...)

	return validations.Validate(v...)
}

// ValidateAuthorizedAdmin determines if the Authorization is valid and an admin.
// TODO See if this can be removed when refactoring auth.
// Optional validation should be passed as parameter to Validate().
func (a Authorization) ValidateAuthorizedAdmin(adminSecret string) func() error {
	return func() error {
		if a.Key != "admin" {
			return fmt.Errorf("must be an authorized admin")
		}

		if a.Secret != adminSecret {
			return fmt.Errorf("must be an authorized admin, invalid admin secret")
		}

		return nil
	}
}

// NewAuthorization provides an Authorization from a header.
// This is separate from admin functions which use the admin env var
func NewAuthorization(authorizationHeader string) (*Authorization, error) {
	var a Authorization
	auth := strings.SplitN(authorizationHeader, ":", 3)
	if len(auth) < 3 {
		return nil, fmt.Errorf("invalid authorization header")
	}
	a.Provider = auth[0]
	a.Key = auth[1]
	a.Secret = auth[2]
	return &a, nil
}

func (v VaultProvider) createPolicyState(name, policy string) error {
	return v.vaultSysSvc.PutPolicy(fmt.Sprintf("%s-%s", vaultProjectPrefix, name), policy)
}

func genProjectAppRole(name string) string {
	return fmt.Sprintf("%s/%s-%s", vaultAppRolePrefix, vaultProjectPrefix, name)
}

func (v VaultProvider) CreateToken(name string) (types.Token, error) {
	token := types.Token{}

	if !v.isAdmin() {
		return token, errors.New("admin credentials must be used to create token")
	}

	secret, err := v.generateSecrets(name)
	if err != nil {
		return token, err
	}

	roleID, err := v.readRoleID(name)
	if err != nil {
		return token, err
	}

	accessor, err := v.readSecretIDAccessor(name, secret.Data["secret_id_accessor"].(string))
	if err != nil {
		return token, err
	}

	token.ProjectID = name
	token.Secret = secret.Data["secret_id"].(string)
	token.ProjectToken.ID = secret.Data["secret_id_accessor"].(string)
	token.RoleID = roleID
	token.CreatedAt = accessor.Data["creation_time"].(string)
	token.ExpiresAt = accessor.Data["expiration_time"].(string)

	return token, nil
}

func (v VaultProvider) CreateProject(name string) (types.Token, error) {
	token := types.Token{}
	if !v.isAdmin() {
		return token, errors.New("admin credentials must be used to create project")
	}

	policy := defaultVaultReadonlyPolicyAWS(name)
	err := v.createPolicyState(name, policy)
	if err != nil {
		return token, err
	}

	if err := v.writeProjectState(name); err != nil {
		return token, err
	}

	return v.CreateToken(name)
}

// CreateTarget creates a target for the project.
// TODO validate policy and other information is correct in target
// TODO Validate role exists (if possible, etc)
func (v VaultProvider) CreateTarget(projectName string, target types.Target) error {
	if !v.isAdmin() {
		return errors.New("admin credentials must be used to create target")
	}

	options := map[string]interface{}{
		"credential_type": target.Properties.CredentialType,
		"policy_arns":     target.Properties.PolicyArns,
		"policy_document": target.Properties.PolicyDocument,
		"role_arns":       target.Properties.RoleArn,
	}

	path := fmt.Sprintf("aws/roles/%s-%s-target-%s", vaultProjectPrefix, projectName, target.Name)
	_, err := v.vaultLogicalSvc.Write(path, options)
	return err
}

func defaultVaultReadonlyPolicyAWS(projectName string) string {
	return fmt.Sprintf(
		"path \"aws/sts/argo-cloudops-projects-%s-target-*\" { capabilities = [\"read\"] }",
		projectName,
	)
}

func (v VaultProvider) deletePolicyState(name string) error {
	return v.vaultSysSvc.DeletePolicy(fmt.Sprintf("%s-%s", vaultProjectPrefix, name))
}

func (v VaultProvider) DeleteProject(name string) error {
	if !v.isAdmin() {
		return errors.New("admin credentials must be used to delete project")
	}

	err := v.deletePolicyState(name)
	if err != nil {
		return fmt.Errorf("vault delete project error: %w", err)
	}

	if _, err = v.vaultLogicalSvc.Delete(genProjectAppRole(name)); err != nil {
		return fmt.Errorf("vault delete project error: %w", err)
	}
	return nil
}

func (v VaultProvider) DeleteTarget(projectName string, targetName string) error {
	if !v.isAdmin() {
		return errors.New("admin credentials must be used to delete target")
	}

	path := fmt.Sprintf("aws/roles/%s-%s-target-%s", vaultProjectPrefix, projectName, targetName)
	_, err := v.vaultLogicalSvc.Delete(path)
	return err
}

const (
	vaultSecretTTL   = "8776h" // 1 year
	vaultTokenMaxTTL = "10m"
	// When set to 1 with the cli or api, it will not return the creds as it
	// says it's hit the limit of uses.
	vaultTokenNumUses = 3
)

func (v VaultProvider) GetProject(projectName string) (responses.GetProject, error) {
	sec, err := v.vaultLogicalSvc.Read(genProjectAppRole(projectName))
	if err != nil {
		return responses.GetProject{}, fmt.Errorf("vault get project error: %w", err)
	}
	if sec == nil {
		return responses.GetProject{}, ErrNotFound
	}

	return responses.GetProject{Name: projectName}, nil
}

func (v VaultProvider) GetTarget(projectName, targetName string) (types.Target, error) {
	if !v.isAdmin() {
		return types.Target{}, errors.New("admin credentials must be used to get target information")
	}

	sec, err := v.vaultLogicalSvc.Read(fmt.Sprintf("aws/roles/argo-cloudops-projects-%s-target-%s", projectName, targetName))
	if err != nil {
		return types.Target{}, fmt.Errorf("vault get target error: %w", err)
	}

	if sec == nil {
		return types.Target{}, ErrTargetNotFound
	}

	// These should always exist.
	roleArn := sec.Data["role_arns"].([]interface{})[0].(string)
	credentialType := sec.Data["credential_type"].(string)

	// Optional.
	policies := []string{}
	if val, ok := sec.Data["policy_arns"]; ok {
		for _, v := range val.([]interface{}) {
			policies = append(policies, v.(string))
		}
	}

	// Optional.
	var policyDocument string
	if val, ok := sec.Data["policy_document"]; ok {
		policyDocument = val.(string)
	}

	return types.Target{
		Name: targetName,
		// target 'Type' always 'aws_account', currently not stored in Vault
		Type: "aws_account",
		Properties: types.TargetProperties{
			CredentialType: credentialType,
			PolicyArns:     policies,
			PolicyDocument: policyDocument,
			RoleArn:        roleArn,
		},
	}, nil
}

func (v VaultProvider) DeleteProjectToken(projectName, tokenID string) error {
	if !v.isAdmin() {
		return errors.New("admin credentials must be used to delete tokens")
	}

	data := map[string]interface{}{
		"secret_id_accessor": tokenID,
	}

	path := fmt.Sprintf("%s/secret-id-accessor/destroy", genProjectAppRole(projectName))
	_, err := v.vaultLogicalSvc.Write(path, data)
	if err != nil {
		return err
	}

	return nil
}

func (v VaultProvider) GetProjectToken(projectName, tokenID string) (types.ProjectToken, error) {
	token := types.ProjectToken{}

	if !v.isAdmin() {
		return token, errors.New("admin credentials must be used to delete tokens")
	}

	data := map[string]interface{}{
		"secret_id_accessor": tokenID,
	}

	path := fmt.Sprintf("%s/secret-id-accessor/lookup", genProjectAppRole(projectName))
	projectToken, err := v.vaultLogicalSvc.Write(path, data)
	if err != nil {
		if !isSecretIDAccessorExists(err) {
			return token, ErrProjectTokenNotFound
		}
		return token, fmt.Errorf("vault get secret ID accessor error: %w", err)
	}

	if projectToken == nil {
		return token, nil
	}

	return types.ProjectToken{
		ID: projectToken.Data["secret_id_accessor"].(string),
	}, nil
}

func (v VaultProvider) GetToken() (string, error) {
	if v.isAdmin() {
		return "", errors.New("admin credentials cannot be used to get tokens")
	}

	options := map[string]interface{}{
		"role_id":   v.roleID,
		"secret_id": v.secretID,
	}

	sec, err := v.vaultLogicalSvc.Write("auth/approle/login", options)
	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}

	return sec.Auth.ClientToken, nil
}

// TODO See if this can be removed when refactoring auth.
func (v VaultProvider) isAdmin() bool {
	return v.roleID == authorizationKeyAdmin
}

func (v VaultProvider) ListTargets(project string) ([]string, error) {
	if !v.isAdmin() {
		return nil, errors.New("admin credentials must be used to list targets")
	}

	sec, err := v.vaultLogicalSvc.List("aws/roles/")
	if err != nil {
		return nil, fmt.Errorf("vault list error: %w", err)
	}

	// allow empty array to render json as []
	list := make([]string, 0)
	if sec != nil {
		for _, target := range sec.Data["keys"].([]interface{}) {
			value := target.(string)
			prefix := fmt.Sprintf("argo-cloudops-projects-%s-target-", project)
			if strings.HasPrefix(value, prefix) {
				list = append(list, strings.Replace(value, prefix, "", 1))
			}
		}
	}

	return list, nil
}

func (v VaultProvider) ProjectExists(name string) (bool, error) {
	p, err := v.GetProject(name)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	return p.Name != "", nil
}

func (v VaultProvider) readRoleID(appRoleName string) (string, error) {
	secret, err := v.vaultLogicalSvc.Read(fmt.Sprintf("%s/role-id", genProjectAppRole(appRoleName)))
	if err != nil {
		return "", err
	}
	return secret.Data["role_id"].(string), nil
}

func (v VaultProvider) readSecretIDAccessor(appRoleName, accessor string) (*vault.Secret, error) {
	options := map[string]interface{}{
		"secret_id_accessor": accessor,
	}

	secret, err := v.vaultLogicalSvc.Write(fmt.Sprintf("%s/secret-id-accessor/lookup", genProjectAppRole(appRoleName)), options)
	if err != nil {
		return secret, err
	}
	return secret, nil
}

func (v VaultProvider) generateSecrets(appRoleName string) (*vault.Secret, error) {
	options := map[string]interface{}{
		"force": true,
	}

	secret, err := v.vaultLogicalSvc.Write(fmt.Sprintf("%s/secret-id", genProjectAppRole(appRoleName)), options)
	if err != nil {
		return secret, err
	}
	return secret, nil
}

func (v VaultProvider) TargetExists(projectName, targetName string) (bool, error) {
	_, err := v.GetTarget(projectName, targetName)
	return !errors.Is(err, ErrTargetNotFound), nil
}

// UpdateTarget updates a targets policies for the project.
func (v VaultProvider) UpdateTarget(projectName string, target types.Target) error {
	if !v.isAdmin() {
		return errors.New("admin credentials must be used to update target")
	}

	options := map[string]interface{}{
		"credential_type": target.Properties.CredentialType,
		"policy_arns":     target.Properties.PolicyArns,
		"policy_document": target.Properties.PolicyDocument,
		"role_arns":       target.Properties.RoleArn,
	}

	path := fmt.Sprintf("aws/roles/%s-%s-target-%s", vaultProjectPrefix, projectName, target.Name)
	_, err := v.vaultLogicalSvc.Write(path, options)
	return err
}

func (v VaultProvider) writeProjectState(name string) error {
	options := map[string]interface{}{
		"secret_id_ttl":           vaultSecretTTL,
		"token_max_ttl":           vaultTokenMaxTTL,
		"token_no_default_policy": "true",
		"token_num_uses":          vaultTokenNumUses,
		"token_policies":          fmt.Sprintf("%s-%s", vaultProjectPrefix, name),
	}

	_, err := v.vaultLogicalSvc.Write(genProjectAppRole(name), options)
	if err != nil {
		return err
	}
	return nil
}

func isSecretIDAccessorExists(err error) bool {
	// Vault does not return a typed error, so unfortunately, the error message must be inspected.
	// More info on this below.
	// https://github.com/hashicorp/vault/issues/2140
	// https://github.com/hashicorp/vault/issues/6868
	// https://github.com/hashicorp/vault/issues/6779
	// https://github.com/hashicorp/vault/pull/6879

	// One other note that could be helpful when typed errors are supported.
	// For versions < 1.9.0, Vault returns a 500 when a secret id accessor cannot be found.
	// In versions >= 1.9.0, a proper status code 404 is being returned.
	// https://github.com/hashicorp/vault/pull/12788
	// https://github.com/hashicorp/vault/releases/tag/v1.9.0
	return !strings.Contains(err.Error(), "failed to find accessor entry for secret_id_accessor")
}

// ProviderV2 is an interface for interacting with credentials providers.
// type ProviderV2 interface {
// 	CreateProject(string) (types.Token, error)
// 	CreateTarget(string, types.Target) error
// 	CreateToken(string) (types.Token, error)
// 	DeleteProject(string) error
// 	DeleteProjectToken(string, string) error
// 	DeleteTarget(string, string) error
// 	GetProject(string) (responses.GetProject, error)
// 	GetProjectToken(string, string) (types.ProjectToken, error)
// 	GetTarget(string, string) (types.Target, error)
// 	GetToken() (string, error)
// 	ListTargets(string) ([]string, error)
// 	ProjectExists(string) (bool, error)
// 	TargetExists(string, string) (bool, error)
// 	UpdateTarget(string, types.Target) error
// }

type ProviderV2 interface {
	CreateProject(CreateProjectArgs) (CreateProjectResponse, error)
	CreateTarget(CreateTargetArgs) (CreateTargetResponse, error)
	CreateToken(CreateTokenArgs) (CreateTokenResponse, error)
	DeleteProject(DeleteProjectArgs) (DeleteProjectResponse, error)
	DeleteProjectToken(DeleteProjectTokenArgs) (DeleteProjectTokenResponse, error)
	DeleteTarget(DeleteTargetArgs) (DeleteTargetResponse, error)
	GetProject(GetProjectArgs) (GetProjectResponse, error)

	// This is used to check if a token exists in
	// the backend. The current implementation uses GetProjectToken to achieve
	// this, but doesn't do anything with the data. GetProjectToken could be an
	// internal implementation detail (instead of being part of the interface/a
	// public method).
	ProjectTokenExists(ProjectTokenExistsArgs) (ProjectTokenExistsResponse, error)
	GetTarget(GetTargetArgs) (GetTargetResponse, error)

	// This is to get a token which can be exchanged for target credentials.
	GetToken(GetTokenArgs) (GetTokenResponse, error)
	ListTargets(ListTargetsArgs) (ListTargetsResponse, error)
	ProjectExists(ProjectExistsArgs) (ProjectExistsResponse, error)
	TargetExists(TargetExistsArgs) (TargetExistsResponse, error)
	UpdateTarget(UpdateTargetArgs) (UpdateTargetResponse, error)
	// TODO make sure all V2 interface methods are implemented
}

// Here is an implementation that talks over RPC
type ProviderV2RPCClient struct {
	client *rpc.Client
}

// CreateProject(string) (types.Token, error)
type CreateProjectArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
}

type CreateProjectResponse struct {
	Token types.Token
}

// CreateTarget(string, types.Target) error
type CreateTargetArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	Target        types.Target
}

type CreateTargetResponse struct {
}

// CreateToken(string) (types.Token, error)
type CreateTokenArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
}

type CreateTokenResponse struct {
	Token types.Token
}

// DeleteProject(string) error
type DeleteProjectArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
}

type DeleteProjectResponse struct {
}

// DeleteProjectToken(string, string) error
type DeleteProjectTokenArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	TokenID       string
}

type DeleteProjectTokenResponse struct {
}

// DeleteTarget(string, string) error
type DeleteTargetArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	TargetName    string
}

type DeleteTargetResponse struct {
}

// GetProject(string) (responses.GetProject, error)
type GetProjectArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
}

type GetProjectResponse struct {
	Project responses.GetProject // TODO change this type?
}

// ProjectTokenExists(string, string) (types.ProjectToken, error)
type ProjectTokenExistsArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	TokenID       string // TODO correct?
}

type ProjectTokenExistsResponse struct {
	Exists bool
}

// GetTarget(string, string) (types.Target, error)
type GetTargetArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	TargetName    string
}

type GetTargetResponse struct {
	Target types.Target
}

// GetToken() (string, error)
type GetTokenArgs struct {
	Authorization Authorization
	Headers       http.Header
	// TODO correct? should we also take a
	// project/target? maybe requires changes in
	// our router/handler?
}

type GetTokenResponse struct {
	Token string // TODO correct? should just be the token value?
}

// ListTargets(string) ([]string, error)
type ListTargetsArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
}

type ListTargetsResponse struct {
	Targets []string
}

// ProjectExists(string) (bool, error)
type ProjectExistsArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
}

type ProjectExistsResponse struct {
	Exists bool
}

// TargetExists(string, string) (bool, error)
type TargetExistsArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	TargetName    string
}

type TargetExistsResponse struct {
	Exists bool
}

// UpdateTarget(string, types.Target) error
type UpdateTargetArgs struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	Target        types.Target
}

type UpdateTargetResponse struct {
}

func (g *ProviderV2RPCClient) CreateProject(args CreateProjectArgs) (CreateProjectResponse, error) {
	var resp CreateProjectResponse
	err := g.client.Call("Plugin.CreateProject", args, &resp)
	// if err != nil {
	// 	return types.Token{}, err
	// 	// // You usually want your interfaces to return errors. If they don't,
	// 	// // there isn't much other choice here.
	// 	// panic(err)
	// }

	return resp, err
}

func (g *ProviderV2RPCClient) CreateTarget(args CreateTargetArgs) (CreateTargetResponse, error) {
	var resp CreateTargetResponse
	err := g.client.Call("Plugin.CreateProject", args, &resp)
	// if err != nil {
	// 	return types.Token{}, err
	// 	// // You usually want your interfaces to return errors. If they don't,
	// 	// // there isn't much other choice here.
	// 	// panic(err)
	// }

	return resp, err
}

// CreateToken(projectName string) (types.Token, error)
func (g *ProviderV2RPCClient) CreateToken(args CreateTokenArgs) (CreateTokenResponse, error) {
	var resp CreateTokenResponse
	err := g.client.Call("Plugin.CreateToken", args, &resp)
	return resp, err
}

// DeleteProject(name string) error
// TODO
func (g *ProviderV2RPCClient) DeleteProject(args DeleteProjectArgs) (DeleteProjectResponse, error) {
	var resp DeleteProjectResponse
	err := g.client.Call("Plugin.DeleteProject", args, &resp)
	return resp, err
}

// DeleteProjectToken(projectName string, tokenID string) error
// TODO
func (g *ProviderV2RPCClient) DeleteProjectToken(args DeleteProjectTokenArgs) (DeleteProjectTokenResponse, error) {
	var resp DeleteProjectTokenResponse
	err := g.client.Call("Plugin.DeleteProjectToken", args, &resp)
	return resp, err
}

// DeleteTarget(projectName string, targetName string) error
// TODO
func (g *ProviderV2RPCClient) DeleteTarget(args DeleteTargetArgs) (DeleteTargetResponse, error) {
	var resp DeleteTargetResponse
	err := g.client.Call("Plugin.DeleteTarget", args, &resp)
	return resp, err
}

// GetProject(name string) (responses.GetProject, error)
func (g *ProviderV2RPCClient) GetProject(args GetProjectArgs) (GetProjectResponse, error) {
	var resp GetProjectResponse
	err := g.client.Call("Plugin.GetProject", args, &resp)
	return resp, err
}

// ProjectTokenExists(projectName string, tokenID string) (types.ProjectToken, error)
func (g *ProviderV2RPCClient) ProjectTokenExists(args ProjectTokenExistsArgs) (ProjectTokenExistsResponse, error) {
	var resp ProjectTokenExistsResponse
	err := g.client.Call("Plugin.ProjectTokenExists", args, &resp)
	return resp, err
}

// GetTarget(projectName string, targetName string) (types.Target, error)
func (g *ProviderV2RPCClient) GetTarget(args GetTargetArgs) (GetTargetResponse, error) {
	var resp GetTargetResponse
	err := g.client.Call("Plugin.GetTarget", args, &resp)
	return resp, err
}

// GetToken() (string, error)
// TODO args correct?
func (g *ProviderV2RPCClient) GetToken(args GetTokenArgs) (GetTokenResponse, error) {
	var resp GetTokenResponse
	err := g.client.Call("Plugin.GetToken", args, &resp)
	return resp, err
}

// ListTargets(projectName string) ([]string, error)
func (g *ProviderV2RPCClient) ListTargets(args ListTargetsArgs) (ListTargetsResponse, error) {
	var resp ListTargetsResponse
	err := g.client.Call("Plugin.ListTargets", args, &resp)
	return resp, err
}

// ProjectExists(projectName string) (bool, error)
func (g *ProviderV2RPCClient) ProjectExists(args ProjectExistsArgs) (ProjectExistsResponse, error) {
	var resp ProjectExistsResponse
	err := g.client.Call("Plugin.ProjectExists", args, &resp)
	return resp, err
}

// TargetExists(projectName string, targetName string) (bool, error)
func (g *ProviderV2RPCClient) TargetExists(args TargetExistsArgs) (TargetExistsResponse, error) {
	var resp TargetExistsResponse
	err := g.client.Call("Plugin.TargetExists", args, &resp)
	return resp, err
}

// UpdateTarget(projectName string, targetName types.Target) error
// TODO
func (g *ProviderV2RPCClient) UpdateTarget(args UpdateTargetArgs) (UpdateTargetResponse, error) {
	var resp UpdateTargetResponse
	err := g.client.Call("Plugin.UpdateTarget", args, &resp)
	return resp, err
}

// Previous implementation
// func (g *ProviderV2RPCClient) CreateProject(name string) (types.Token, error) {
// 	var resp types.Token
// 	err := g.client.Call("Plugin.CreateProject", name, &resp)
// 	// if err != nil {
// 	// 	return types.Token{}, err
// 	// 	// // You usually want your interfaces to return errors. If they don't,
// 	// 	// // there isn't much other choice here.
// 	// 	// panic(err)
// 	// }

// 	return resp, err
// }

// // CreateToken(projectName string) (types.Token, error)
// func (g *ProviderV2RPCClient) CreateToken(projectName string) (types.Token, error) {
// 	var resp types.Token
// 	err := g.client.Call("Plugin.CreateToken", projectName, &resp)
// 	return resp, err
// }

// // DeleteProject(name string) error
// func (g *ProviderV2RPCClient) DeleteProject(name string) error {
// 	return g.client.Call("Plugin.DeleteProject", name, nil)
// }

// // DeleteProjectToken(projectName string, tokenID string) error
// func (g *ProviderV2RPCClient) DeleteProjectToken(projectName string, tokenID string) error {
// 	return g.client.Call("Plugin.DeleteProjectToken", projectName, tokenID)
// }

// // DeleteTarget(projectName string, targetName string) error
// func (g *ProviderV2RPCClient) DeleteTarget(projectName string, targetName string) error {
// 	return g.client.Call("Plugin.DeleteTarget", projectName)
// }

// // GetProject(name string) (responses.GetProject, error)
// func (g *ProviderV2RPCClient) GetProject(name string) (responses.GetProject, error) {
// 	var resp responses.GetProject
// 	err := g.client.Call("Plugin.GetProject", name, &resp)
// 	return resp, err
// }

// // GetProjectToken(projectName string, tokenID string) (types.ProjectToken, error)
// func (g *ProviderV2RPCClient) GetProjectToken(projectName string, tokenID string) (types.ProjectToken, error) {
// 	var resp types.ProjectToken
// 	err := g.client.Call("Plugin.GetProjectToken", projectName, &resp)
// 	return resp, err
// }

// // GetTarget(projectName string, targetName string) (types.Target, error)
// func (g *ProviderV2RPCClient) GetTarget(projectName string, targetName string) (types.Target, error) {
// 	var resp types.Target
// 	err := g.client.Call("Plugin.GetTarget", projectName, &resp)
// 	return resp, err
// }

// // GetToken() (string, error)
// func (g *ProviderV2RPCClient) GetToken() (string, error) {
// 	var resp string
// 	err := g.client.Call("Plugin.GetToken", &resp)
// 	return resp, err
// }

// // ListTargets(projectName string) ([]string, error)
// func (g *ProviderV2RPCClient) ListTargets(projectName string) ([]string, error) {
// 	var resp []string
// 	err := g.client.Call("Plugin.ListTargets", projectName, &resp)
// 	return resp, err
// }

// // ProjectExists(projectName string) (bool, error)
// func (g *ProviderV2RPCClient) ProjectExists(projectName string) (bool, error) {
// 	var resp bool
// 	err := g.client.Call("Plugin.ProjectExists", projectName, &resp)
// 	return resp, err
// }

// // TargetExists(projectName string, targetName string) (bool, error)
// func (g *ProviderV2RPCClient) TargetExists(projectName string, targetName string) (bool, error) {
// 	var resp bool
// 	err := g.client.Call("Plugin.TargetExists", projectName, &resp)
// 	return resp, err
// }

// // UpdateTarget(projectName string, targetName types.Target) error
// func (g *ProviderV2RPCClient) UpdateTarget(projectName string, targetName types.Target) error {
// 	return g.client.Call("Plugin.UpdateTarget", projectName)
// }

// func (g *ProviderV2RPCClient) CreateTarget(name string) (types.Target, error) {
// 	var resp types.Target
// 	err := g.client.Call("Plugin.CreateProject", name, &resp)
// 	// if err != nil {
// 	// 	return types.Token{}, err
// 	// 	// // You usually want your interfaces to return errors. If they don't,
// 	// 	// // there isn't much other choice here.
// 	// 	// panic(err)
// 	// }

// 	return resp, err
// }

// Here is the RPC server that ProviderV2RPC talks to, conforming to
// the requirements of net/rpc
type ProviderV2RPCServer struct {
	// This is the real implementation
	Impl ProviderV2
}

// TODO not sure if this is the best way to handle accepting/returning args
func (s *ProviderV2RPCServer) CreateProject(args CreateProjectArgs, resp *CreateProjectResponse) error {
	v, err := s.Impl.CreateProject(args)
	*resp = v
	return err
}

func (s *ProviderV2RPCServer) CreateTarget(args CreateTargetArgs, resp *CreateTargetResponse) error {
	v, err := s.Impl.CreateTarget(args)
	*resp = v
	return err
}

func (s *ProviderV2RPCServer) CreateToken(args CreateTokenArgs, resp *CreateTokenResponse) error {
	v, err := s.Impl.CreateToken(args)
	*resp = v
	return err
}

func (s *ProviderV2RPCServer) ProjectExists(args ProjectExistsArgs, resp *ProjectExistsResponse) error {
	v, err := s.Impl.ProjectExists(args)
	*resp = v
	return err
}

func (s *ProviderV2RPCServer) TargetExists(args TargetExistsArgs, resp *TargetExistsResponse) error {
	v, err := s.Impl.TargetExists(args)
	*resp = v
	return err
}

// This is the implementation of plugin.Plugin so we can serve/consume this
//
// This has two methods: Server must return an RPC server for this plugin
// type. We construct a ProviderV2RPCServer for this.
//
// Client must return an implementation of our interface that communicates
// over an RPC client. We return ProviderV2RPC for this.
//
// Ignore MuxBroker. That is used to create more multiplexed streams on our
// plugin connection and is a more advanced use case.
type ProviderV2Plugin struct {
	// Impl Injection
	Impl ProviderV2
}

func (p *ProviderV2Plugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &ProviderV2RPCServer{Impl: p.Impl}, nil
}

func (ProviderV2Plugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &ProviderV2RPCClient{client: c}, nil
}
