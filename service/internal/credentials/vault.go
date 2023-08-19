//go:generate moq -out ../../test/testhelpers/credsProvider.go -pkg testhelpers . Provider:CredsProviderMock

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

// TODO needed?
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

type Provider interface {
	CreateProject(CreateProjectInput) (CreateProjectOutput, error)
	CreateTarget(CreateTargetInput) (CreateTargetOutput, error)
	CreateToken(CreateTokenInput) (CreateTokenOutput, error)
	DeleteProject(DeleteProjectInput) (DeleteProjectOutput, error)
	DeleteProjectToken(DeleteProjectTokenInput) (DeleteProjectTokenOutput, error)
	DeleteTarget(DeleteTargetInput) (DeleteTargetOutput, error)
	GetProject(GetProjectInput) (GetProjectOutput, error)

	// This is used to check if a token exists in
	// the backend. The current implementation uses GetProjectToken to achieve
	// this, but doesn't do anything with the data. GetProjectToken could be an
	// internal implementation detail (instead of being part of the interface/a
	// public method).
	ProjectTokenExists(ProjectTokenExistsInput) (ProjectTokenExistsOutput, error)
	GetTarget(GetTargetInput) (GetTargetOutput, error)

	// This is to get a token which can be exchanged for target credentials.
	GetToken(GetTokenInput) (GetTokenOutput, error)
	ListTargets(ListTargetsInput) (ListTargetsOutput, error)
	ProjectExists(ProjectExistsInput) (ProjectExistsOutput, error)
	TargetExists(TargetExistsInput) (TargetExistsOutput, error)
	UpdateTarget(UpdateTargetInput) (UpdateTargetOutput, error)
	// TODO make sure all V2 interface methods are implemented
}

// Here is an implementation that talks over RPC
type ProviderV2RPCClient struct {
	client *rpc.Client
}

type CreateProjectInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
}

type CreateProjectOutput struct {
	Token types.Token
}

type CreateTargetInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	Target        types.Target
}

type CreateTargetOutput struct {
}

type CreateTokenInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
}

type CreateTokenOutput struct {
	Token types.Token
}

type DeleteProjectInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
}

type DeleteProjectOutput struct {
}

type DeleteProjectTokenInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	TokenID       string
}

type DeleteProjectTokenOutput struct {
}

type DeleteTargetInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	TargetName    string
}

type DeleteTargetOutput struct {
}

type GetProjectInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
}

type GetProjectOutput struct {
	Project responses.GetProject // TODO change this type?
}

type ProjectTokenExistsInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	TokenID       string // TODO correct?
}

type ProjectTokenExistsOutput struct {
	Exists bool
}

type GetTargetInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	TargetName    string
}

type GetTargetOutput struct {
	Target types.Target
}

type GetTokenInput struct {
	Authorization Authorization
	Headers       http.Header
	// TODO correct? should we also take a
	// project/target? maybe requires changes in
	// our router/handler?
}

type GetTokenOutput struct {
	Token string // TODO correct? should just be the token value?
}

type ListTargetsInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
}

type ListTargetsOutput struct {
	Targets []string
}

type ProjectExistsInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
}

type ProjectExistsOutput struct {
	Exists bool
}

type TargetExistsInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	TargetName    string
}

type TargetExistsOutput struct {
	Exists bool
}

type UpdateTargetInput struct {
	Authorization Authorization
	Headers       http.Header
	ProjectName   string
	Target        types.Target
}

type UpdateTargetOutput struct {
}

func (g *ProviderV2RPCClient) CreateProject(input CreateProjectInput) (CreateProjectOutput, error) {
	var output CreateProjectOutput
	err := g.client.Call("Plugin.CreateProject", input, &output)
	return output, err
}

func (g *ProviderV2RPCClient) CreateTarget(input CreateTargetInput) (CreateTargetOutput, error) {
	var output CreateTargetOutput
	err := g.client.Call("Plugin.CreateTarget", input, &output)
	return output, err
}

func (g *ProviderV2RPCClient) CreateToken(input CreateTokenInput) (CreateTokenOutput, error) {
	var output CreateTokenOutput
	err := g.client.Call("Plugin.CreateToken", input, &output)
	return output, err
}

// TODO
func (g *ProviderV2RPCClient) DeleteProject(input DeleteProjectInput) (DeleteProjectOutput, error) {
	var output DeleteProjectOutput
	err := g.client.Call("Plugin.DeleteProject", input, &output)
	return output, err
}

// TODO
func (g *ProviderV2RPCClient) DeleteProjectToken(input DeleteProjectTokenInput) (DeleteProjectTokenOutput, error) {
	var output DeleteProjectTokenOutput
	err := g.client.Call("Plugin.DeleteProjectToken", input, &output)
	return output, err
}

// TODO
func (g *ProviderV2RPCClient) DeleteTarget(input DeleteTargetInput) (DeleteTargetOutput, error) {
	var output DeleteTargetOutput
	err := g.client.Call("Plugin.DeleteTarget", input, &output)
	return output, err
}

func (g *ProviderV2RPCClient) GetProject(input GetProjectInput) (GetProjectOutput, error) {
	var output GetProjectOutput
	err := g.client.Call("Plugin.GetProject", input, &output)
	return output, err
}

func (g *ProviderV2RPCClient) ProjectTokenExists(input ProjectTokenExistsInput) (ProjectTokenExistsOutput, error) {
	var output ProjectTokenExistsOutput
	err := g.client.Call("Plugin.ProjectTokenExists", input, &output)
	return output, err
}

func (g *ProviderV2RPCClient) GetTarget(input GetTargetInput) (GetTargetOutput, error) {
	var output GetTargetOutput
	err := g.client.Call("Plugin.GetTarget", input, &output)
	return output, err
}

// TODO input correct?
func (g *ProviderV2RPCClient) GetToken(input GetTokenInput) (GetTokenOutput, error) {
	var output GetTokenOutput
	err := g.client.Call("Plugin.GetToken", input, &output)
	return output, err
}

func (g *ProviderV2RPCClient) ListTargets(input ListTargetsInput) (ListTargetsOutput, error) {
	var output ListTargetsOutput
	err := g.client.Call("Plugin.ListTargets", input, &output)
	return output, err
}

func (g *ProviderV2RPCClient) ProjectExists(input ProjectExistsInput) (ProjectExistsOutput, error) {
	var output ProjectExistsOutput
	err := g.client.Call("Plugin.ProjectExists", input, &output)
	return output, err
}

func (g *ProviderV2RPCClient) TargetExists(input TargetExistsInput) (TargetExistsOutput, error) {
	var output TargetExistsOutput
	err := g.client.Call("Plugin.TargetExists", input, &output)
	return output, err
}

// TODO
func (g *ProviderV2RPCClient) UpdateTarget(input UpdateTargetInput) (UpdateTargetOutput, error) {
	var output UpdateTargetOutput
	err := g.client.Call("Plugin.UpdateTarget", input, &output)
	return output, err
}

// Here is the RPC server that ProviderV2RPC talks to, conforming to
// the requirements of net/rpc
type ProviderV2RPCServer struct {
	// This is the real implementation
	Impl Provider
}

// TODO not sure if this is the best way to handle accepting/returning args
func (s *ProviderV2RPCServer) CreateProject(input CreateProjectInput, output *CreateProjectOutput) error {
	v, err := s.Impl.CreateProject(input)
	*output = v
	return err
}

func (s *ProviderV2RPCServer) CreateTarget(input CreateTargetInput, output *CreateTargetOutput) error {
	v, err := s.Impl.CreateTarget(input)
	*output = v
	return err
}

func (s *ProviderV2RPCServer) CreateToken(input CreateTokenInput, output *CreateTokenOutput) error {
	v, err := s.Impl.CreateToken(input)
	*output = v
	return err
}

func (s *ProviderV2RPCServer) GetToken(input GetTokenInput, output *GetTokenOutput) error {
	v, err := s.Impl.GetToken(input)
	*output = v
	return err
}

func (s *ProviderV2RPCServer) ProjectExists(input ProjectExistsInput, output *ProjectExistsOutput) error {
	v, err := s.Impl.ProjectExists(input)
	*output = v
	return err
}

func (s *ProviderV2RPCServer) TargetExists(input TargetExistsInput, output *TargetExistsOutput) error {
	v, err := s.Impl.TargetExists(input)
	*output = v
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
	Impl Provider
}

func (p *ProviderV2Plugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &ProviderV2RPCServer{Impl: p.Impl}, nil
}

func (ProviderV2Plugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &ProviderV2RPCClient{client: c}, nil
}
