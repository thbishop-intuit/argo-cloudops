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

	"github.com/hashicorp/go-plugin"
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

var (
	// ErrNotFound conveys that the item was not found.
	ErrNotFound = errors.New("item not found")
	// ErrTargetNotFound conveys that the target was not round.
	ErrTargetNotFound = errors.New("target not found")
	// ErrProjectTokenNotFound conveys that the token was not found.
	ErrProjectTokenNotFound = errors.New("project token not found")
)

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
	return resp, err
}

func (g *ProviderV2RPCClient) CreateTarget(args CreateTargetArgs) (CreateTargetResponse, error) {
	var resp CreateTargetResponse
	err := g.client.Call("Plugin.CreateProject", args, &resp)
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
