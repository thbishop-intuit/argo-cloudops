package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/cello-proj/cello/internal/types"
	"github.com/cello-proj/cello/service/internal/credentials"
	"github.com/hashicorp/go-hclog"
	vault "github.com/hashicorp/vault/api"
)

const (
	authorizationKeyAdmin = "admin"
)

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
	// TODO does this need to be elevated to a first class error that
	// plugins can return?
	ErrNotFound = errors.New("item not found")
	// ErrTargetNotFound conveys that the target was not round.
	// TODO does this need to be elevated to a first class error that
	// plugins can return?
	ErrTargetNotFound = errors.New("target not found")
	// ErrProjectTokenNotFound conveys that the token was not found.
	// TODO does this need to be elevated to a first class error that
	// plugins can return?
	ErrProjectTokenNotFound = errors.New("project token not found")
)

type vaultSvc struct {
	roleID          string
	secretID        string
	vaultLogicalSvc vaultLogical
	vaultSysSvc     vaultSys
}

func (v *vaultSvc) isAdmin() bool {
	return v.roleID == authorizationKeyAdmin
}

func (v *vaultSvc) createPolicyState(name, policy string) error {
	return v.vaultSysSvc.PutPolicy(fmt.Sprintf("%s-%s", vaultProjectPrefix, name), policy)
}

func (v *vaultSvc) writeProjectState(name string) error {
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

func (v *vaultSvc) generateSecrets(appRoleName string) (*vault.Secret, error) {
	options := map[string]interface{}{
		"force": true,
	}

	secret, err := v.vaultLogicalSvc.Write(fmt.Sprintf("%s/secret-id", genProjectAppRole(appRoleName)), options)
	if err != nil {
		return secret, err
	}
	return secret, nil
}

func (v *vaultSvc) readRoleID(appRoleName string) (string, error) {
	secret, err := v.vaultLogicalSvc.Read(fmt.Sprintf("%s/role-id", genProjectAppRole(appRoleName)))
	if err != nil {
		return "", err
	}
	return secret.Data["role_id"].(string), nil
}

func (v *vaultSvc) readSecretIDAccessor(appRoleName, accessor string) (*vault.Secret, error) {
	options := map[string]interface{}{
		"secret_id_accessor": accessor,
	}

	secret, err := v.vaultLogicalSvc.Write(fmt.Sprintf("%s/secret-id-accessor/lookup", genProjectAppRole(appRoleName)), options)
	if err != nil {
		return secret, err
	}
	return secret, nil
}

type VaultProvider struct {
	vaultSvcFn func(auth credentials.Authorization, h http.Header) (vaultSvc, error)
	// TODO unwind this along with new provider, etc?
	logger          hclog.Logger
	roleID          string
	secretID        string
	vaultLogicalSvc vaultLogical
	vaultSysSvc     vaultSys
}

func newVaultSvc(auth credentials.Authorization, h http.Header) (vaultSvc, error) {
	config := NewVaultConfig(
		&vault.Config{Address: os.Getenv("VAULT_ADDR")},
		os.Getenv("VAULT_ROLE"),
		os.Getenv("VAULT_SECRET"),
	)
	svc, err := NewVaultSvc(*config, h)
	if err != nil {
		return vaultSvc{}, err
	}

	return vaultSvc{
		vaultLogicalSvc: vaultLogical(svc.Logical()),
		vaultSysSvc:     vaultSys(svc.Sys()),
		roleID:          auth.Key,
		secretID:        auth.Secret,
	}, nil
}

// NewVaultProvider returns a new VaultProvider
func NewVaultProvider(a credentials.Authorization, h http.Header) (credentials.Provider, error) {
	// config := vaultConfigFn(&vault.Config{Address: env.VaultAddress}, env.VaultRole, env.VaultSecret)
	config := NewVaultConfig(
		&vault.Config{Address: os.Getenv("VAULT_ADDR")},
		os.Getenv("VAULT_ROLE"),
		os.Getenv("VAULT_SECRET"),
	)
	svc, err := NewVaultSvc(*config, h)
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

func genProjectAppRole(name string) string {
	return fmt.Sprintf("%s/%s-%s", vaultAppRolePrefix, vaultProjectPrefix, name)
}

func (v *VaultProvider) CreateToken(args credentials.CreateTokenArgs) (credentials.CreateTokenResponse, error) {
	resp := credentials.CreateTokenResponse{}
	projectName := args.ProjectName

	svc, err := v.vaultSvcFn(args.Authorization, args.Headers)
	if err != nil {
		return resp, err
	}

	if !svc.isAdmin() {
		return resp, errors.New("admin credentials must be used to create token")
	}

	secret, err := svc.generateSecrets(projectName)
	if err != nil {
		return resp, err
	}

	roleID, err := svc.readRoleID(projectName)
	if err != nil {
		return resp, err
	}

	accessor, err := svc.readSecretIDAccessor(projectName, secret.Data["secret_id_accessor"].(string))
	if err != nil {
		return resp, err
	}

	resp.Token = types.Token{
		ProjectID: projectName,
		Secret:    secret.Data["secret_id"].(string),
		ProjectToken: types.ProjectToken{
			ID: secret.Data["secret_id_accessor"].(string),
		},
		RoleID:    roleID,
		CreatedAt: accessor.Data["creation_time"].(string),
		ExpiresAt: accessor.Data["expiration_time"].(string),
	}

	return resp, nil
}

func (v *VaultProvider) CreateProject(args credentials.CreateProjectArgs) (credentials.CreateProjectResponse, error) {
	name := args.ProjectName
	resp := credentials.CreateProjectResponse{}

	svc, err := v.vaultSvcFn(args.Authorization, args.Headers)
	if err != nil {
		return resp, err
	}

	if !svc.isAdmin() {
		return resp, errors.New("admin credentials must be used to create project")
	}

	policy := defaultVaultReadonlyPolicyAWS(name)
	if err = svc.createPolicyState(name, policy); err != nil {
		return resp, err
	}

	if err := svc.writeProjectState(name); err != nil {
		return resp, err
	}

	token, err := v.CreateToken(credentials.CreateTokenArgs{
		Authorization: args.Authorization,
		Headers:       args.Headers,
		ProjectName:   name,
	})
	if err != nil {
		return resp, err
	}

	resp.Token = token.Token

	return resp, nil
}

// CreateTarget creates a target for the project.
// TODO validate policy and other information is correct in target
// TODO Validate role exists (if possible, etc)
func (v *VaultProvider) CreateTarget(args credentials.CreateTargetArgs) (credentials.CreateTargetResponse, error) {
	log.Println("inside create target vault plugin - stdlogger")
	resp := credentials.CreateTargetResponse{}

	svc, err := v.vaultSvcFn(args.Authorization, args.Headers)
	if err != nil {
		return resp, err
	}

	if !svc.isAdmin() {
		return resp, errors.New("admin credentials must be used to create target")
	}

	projectName := args.ProjectName
	target := args.Target

	options := map[string]interface{}{
		"credential_type": target.Properties.CredentialType,
		"policy_arns":     target.Properties.PolicyArns,
		"policy_document": target.Properties.PolicyDocument,
		"role_arns":       target.Properties.RoleArn,
	}

	path := fmt.Sprintf("aws/roles/%s-%s-target-%s", vaultProjectPrefix, projectName, target.Name)
	_, err = svc.vaultLogicalSvc.Write(path, options)
	return resp, err
}

func defaultVaultReadonlyPolicyAWS(projectName string) string {
	return fmt.Sprintf(
		"path \"aws/sts/argo-cloudops-projects-%s-target-*\" { capabilities = [\"read\"] }",
		projectName,
	)
}

func (v *VaultProvider) DeleteProject(args credentials.DeleteProjectArgs) (credentials.DeleteProjectResponse, error) {
	resp := credentials.DeleteProjectResponse{}
	projectName := args.ProjectName

	svc, err := v.vaultSvcFn(args.Authorization, args.Headers)
	if err != nil {
		return resp, err
	}

	if !svc.isAdmin() {
		return resp, errors.New("admin credentials must be used to delete projects")
	}

	if err := svc.vaultSysSvc.DeletePolicy(fmt.Sprintf("%s-%s", vaultProjectPrefix, projectName)); err != nil {
		return resp, fmt.Errorf("vault delete project error: %w", err)
	}

	if _, err = svc.vaultLogicalSvc.Delete(genProjectAppRole(projectName)); err != nil {
		return resp, fmt.Errorf("vault delete project error: %w", err)
	}

	return resp, nil
}

func (v *VaultProvider) DeleteTarget(args credentials.DeleteTargetArgs) (credentials.DeleteTargetResponse, error) {
	projectName := args.ProjectName
	targetName := args.ProjectName
	resp := credentials.DeleteTargetResponse{}

	svc, err := v.vaultSvcFn(args.Authorization, args.Headers)
	if err != nil {
		return resp, err
	}

	if !svc.isAdmin() {
		return resp, errors.New("admin credentials must be used to delete targets")
	}

	path := fmt.Sprintf("aws/roles/%s-%s-target-%s", vaultProjectPrefix, projectName, targetName)
	_, err = svc.vaultLogicalSvc.Delete(path)
	return resp, err
}

const (
	vaultSecretTTL   = "8776h" // 1 year
	vaultTokenMaxTTL = "10m"
	// When set to 1 with the cli or api, it will not return the creds as it
	// says it's hit the limit of uses.
	vaultTokenNumUses = 3
)

// TODO this does not require admin credentials; should it?
func (v *VaultProvider) GetProject(args credentials.GetProjectArgs) (credentials.GetProjectResponse, error) {
	name := args.ProjectName
	resp := credentials.GetProjectResponse{}

	svc, err := v.vaultSvcFn(args.Authorization, args.Headers)
	if err != nil {
		return resp, err
	}

	sec, err := svc.vaultLogicalSvc.Read(genProjectAppRole(name))
	if err != nil {
		return resp, fmt.Errorf("vault get project error: %w", err)
	}

	if sec == nil {
		return resp, ErrNotFound
	}

	resp.Project.Name = name

	return resp, nil
}

func (v *VaultProvider) GetTarget(args credentials.GetTargetArgs) (credentials.GetTargetResponse, error) {
	projName := args.ProjectName
	targetName := args.TargetName
	resp := credentials.GetTargetResponse{}

	svc, err := v.vaultSvcFn(args.Authorization, args.Headers)
	if err != nil {
		return resp, err
	}

	// TODO we previously had this, but it's also used to make sure the
	// target exists when creating a workflow (which is not using admin
	// credentials). When we migrate authorization out of the credential
	// providers, this check will be elevated in the call stack so this
	// won't be an issue.
	// if !svc.isAdmin() {
	// 	return resp, errors.New("admin credentials must be used to get target information")
	// }

	sec, err := svc.vaultLogicalSvc.Read(fmt.Sprintf("aws/roles/argo-cloudops-projects-%s-target-%s", projName, targetName))
	if err != nil {
		return resp, fmt.Errorf("vault get target error: %w", err)
	}

	if sec == nil {
		return resp, ErrTargetNotFound
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

	resp.Target.Name = targetName
	resp.Target.Type = "aws_account"
	resp.Target.Properties.CredentialType = credentialType
	resp.Target.Properties.PolicyArns = policies
	resp.Target.Properties.PolicyDocument = policyDocument
	resp.Target.Properties.RoleArn = roleArn

	return resp, nil
}

func (v *VaultProvider) DeleteProjectToken(args credentials.DeleteProjectTokenArgs) (credentials.DeleteProjectTokenResponse, error) {
	projectName := args.ProjectName
	tokenID := args.TokenID
	resp := credentials.DeleteProjectTokenResponse{}

	svc, err := v.vaultSvcFn(args.Authorization, args.Headers)
	if err != nil {
		return resp, err
	}

	if !svc.isAdmin() {
		return resp, errors.New("admin credentials must be used to delete tokens")
	}

	data := map[string]interface{}{
		"secret_id_accessor": tokenID,
	}

	path := fmt.Sprintf("%s/secret-id-accessor/destroy", genProjectAppRole(projectName))
	_, err = v.vaultLogicalSvc.Write(path, data)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

func (v *VaultProvider) ProjectTokenExists(args credentials.ProjectTokenExistsArgs) (credentials.ProjectTokenExistsResponse, error) {
	projectName := args.ProjectName
	tokenID := args.TokenID

	resp := credentials.ProjectTokenExistsResponse{}

	svc, err := v.vaultSvcFn(args.Authorization, args.Headers)
	if err != nil {
		return resp, err
	}

	if !svc.isAdmin() {
		return resp, errors.New("admin credentials must be used to get a token")
	}

	data := map[string]interface{}{
		"secret_id_accessor": tokenID,
	}

	path := fmt.Sprintf("%s/secret-id-accessor/lookup", genProjectAppRole(projectName))
	projectToken, err := svc.vaultLogicalSvc.Write(path, data)
	if err != nil {
		if !isSecretIDAccessorExists(err) {
			resp.Exists = false
			return resp, nil
		}
		return resp, fmt.Errorf("vault get secret ID accessor error: %w", err)
	}

	// TODO not sure why this would be nil. this was carried over from old
	// code.
	resp.Exists = projectToken != nil

	return resp, nil
}

func (v *VaultProvider) GetToken(args credentials.GetTokenArgs) (credentials.GetTokenResponse, error) {
	resp := credentials.GetTokenResponse{}

	svc, err := v.vaultSvcFn(args.Authorization, args.Headers)
	if err != nil {
		return resp, err
	}

	if svc.isAdmin() {
		return resp, errors.New("admin credentials cannot be used to get tokens")
	}

	options := map[string]interface{}{
		// "role_id":   v.roleID,
		// "secret_id": v.secretID,
		"role_id":   svc.roleID,
		"secret_id": svc.secretID,
	}

	println(fmt.Sprintf("role_id: %s", v.roleID))
	println(fmt.Sprintf("secret_id: %s", v.secretID))

	sec, err := svc.vaultLogicalSvc.Write("auth/approle/login", options)
	if err != nil {
		return resp, err
	}

	resp.Token = sec.Auth.ClientToken

	return resp, nil
}

// TODO See if this can be removed when refactoring auth.
func (v *VaultProvider) isAdmin() bool {
	return v.roleID == authorizationKeyAdmin
}

func (v VaultProvider) ListTargets(args credentials.ListTargetsArgs) (credentials.ListTargetsResponse, error) {
	projectName := args.ProjectName
	resp := credentials.ListTargetsResponse{}

	svc, err := v.vaultSvcFn(args.Authorization, args.Headers)
	if err != nil {
		return resp, err
	}

	if !svc.isAdmin() {
		return resp, errors.New("admin credentials must be used to list targets")
	}

	sec, err := svc.vaultLogicalSvc.List("aws/roles/")
	if err != nil {
		return resp, fmt.Errorf("vault list error: %w", err)
	}

	// allow empty array to render json as []
	resp.Targets = []string{}
	if sec != nil {
		for _, target := range sec.Data["keys"].([]interface{}) {
			value := target.(string)
			prefix := fmt.Sprintf("argo-cloudops-projects-%s-target-", projectName)
			if strings.HasPrefix(value, prefix) {
				resp.Targets = append(resp.Targets, strings.Replace(value, prefix, "", 1))
			}
		}
	}

	return resp, nil
}

func (v *VaultProvider) ProjectExists(args credentials.ProjectExistsArgs) (credentials.ProjectExistsResponse, error) {
	resp := credentials.ProjectExistsResponse{}
	name := args.ProjectName

	p, err := v.GetProject(credentials.GetProjectArgs{
		Authorization: args.Authorization,
		Headers:       args.Headers,
		ProjectName:   name,
	})

	if errors.Is(err, ErrNotFound) {
		return resp, nil
	}

	if err != nil {
		return resp, err
	}

	resp.Exists = p.Project.Name != ""

	return resp, nil
}

func (v *VaultProvider) readRoleID(appRoleName string) (string, error) {
	secret, err := v.vaultLogicalSvc.Read(fmt.Sprintf("%s/role-id", genProjectAppRole(appRoleName)))
	if err != nil {
		return "", err
	}
	return secret.Data["role_id"].(string), nil
}

func (v *VaultProvider) readSecretIDAccessor(appRoleName, accessor string) (*vault.Secret, error) {
	options := map[string]interface{}{
		"secret_id_accessor": accessor,
	}

	secret, err := v.vaultLogicalSvc.Write(fmt.Sprintf("%s/secret-id-accessor/lookup", genProjectAppRole(appRoleName)), options)
	if err != nil {
		return secret, err
	}
	return secret, nil
}

func (v *VaultProvider) generateSecrets(appRoleName string) (*vault.Secret, error) {
	options := map[string]interface{}{
		"force": true,
	}

	secret, err := v.vaultLogicalSvc.Write(fmt.Sprintf("%s/secret-id", genProjectAppRole(appRoleName)), options)
	if err != nil {
		return secret, err
	}
	return secret, nil
}

func (v *VaultProvider) TargetExists(args credentials.TargetExistsArgs) (credentials.TargetExistsResponse, error) {
	resp := credentials.TargetExistsResponse{}
	projName := args.ProjectName
	targetName := args.TargetName

	t, err := v.GetTarget(credentials.GetTargetArgs{
		Authorization: args.Authorization,
		Headers:       args.Headers,
		ProjectName:   projName,
		TargetName:    targetName,
	})
	// TODO this wasn't handling errors properly - we're now using the same
	// approach as ProjectExists
	if errors.Is(err, ErrTargetNotFound) {
		return resp, nil
	}

	if err != nil {
		return resp, err
	}

	resp.Exists = t.Target.Name != ""

	return resp, nil
}

// UpdateTarget updates a targets policies for the project.
func (v *VaultProvider) UpdateTarget(args credentials.UpdateTargetArgs) (credentials.UpdateTargetResponse, error) {
	resp := credentials.UpdateTargetResponse{}
	projectName := args.ProjectName
	targetName := args.Target.Name

	svc, err := v.vaultSvcFn(args.Authorization, args.Headers)
	if err != nil {
		return resp, err
	}

	if !svc.isAdmin() {
		return resp, errors.New("admin credentials must be used to update targets")
	}

	options := map[string]interface{}{
		"credential_type": args.Target.Properties.CredentialType,
		"policy_arns":     args.Target.Properties.PolicyArns,
		"policy_document": args.Target.Properties.PolicyDocument,
		"role_arns":       args.Target.Properties.RoleArn,
	}

	path := fmt.Sprintf("aws/roles/%s-%s-target-%s", vaultProjectPrefix, projectName, targetName)
	_, err = svc.vaultLogicalSvc.Write(path, options)
	return resp, err
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
