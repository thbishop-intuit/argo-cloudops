//go:build !test
// +build !test

package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"

	"github.com/cello-proj/cello/internal/validations"
	"github.com/cello-proj/cello/service/internal/credentials"
	"github.com/cello-proj/cello/service/internal/db"
	"github.com/cello-proj/cello/service/internal/env"
	"github.com/cello-proj/cello/service/internal/git"
	"github.com/cello-proj/cello/service/internal/workflow"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	"github.com/argoproj/argo-workflows/v3/cmd/argo/commands/client"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

var (
// Populated during build/release
// TODO expose these.
// commit  string
// date    string
// version string
)

func main() {
	var (
		logger    = log.With(log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout)), "ts", log.DefaultTimestampUTC)
		errLogger = log.With(log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr)), "ts", log.DefaultTimestampUTC)
	)

	env, err := env.GetEnv()
	if err != nil {
		panic(fmt.Sprintf("Unable to initialize environment variables %s", err))
	}

	setLogLevel(&logger, env.LogLevel)

	level.Info(logger).Log("message", fmt.Sprintf("loading config '%s'", env.ConfigFilePath))
	config, err := loadConfig(env.ConfigFilePath)
	if err != nil {
		panic(fmt.Sprintf("Unable to load config %s", err))
	}
	level.Info(logger).Log("message", fmt.Sprintf("loading config '%s' completed", env.ConfigFilePath))

	// temp, will rm after config restructure
	validations.SetImageURIs(env.ImageURIs)

	// The Argo context is needed for any Argo client method calls or else, nil errors.
	argoCtx, argoClient := client.NewAPIClient()

	dbClient, err := db.NewSQLClient(env.DBHost, env.DBName, env.DBUser, env.DBPassword)
	if err != nil {
		level.Error(errLogger).Log("message", "error creating db client", "error", err)
		os.Exit(1)
	}

	// TODO what should this really be?
	handshakeConfig := plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "BASIC_PLUGIN",
		MagicCookieValue: "hello",
	}

	// TODO not sure if this is a good way to handle these plugins (especially
	// for cleaning up). Do we need to keep a ref to the actual client?
	credPlugins := []string{"vault"}
	credPluginsClients := map[string]credentials.Provider{}

	pluginMap := map[string]plugin.Plugin{}

	for _, name := range credPlugins {
		pluginMap[name] = &credentials.ProviderPlugin{}

	}

	pluginLogger := hclog.New(&hclog.LoggerOptions{
		Name:   "plugin",
		Output: os.Stdout,
		Level:  hclog.Debug,
	})

	for _, name := range credPlugins {
		client := plugin.NewClient(&plugin.ClientConfig{
			HandshakeConfig: handshakeConfig,
			Plugins:         pluginMap,
			// TODO update to be dynamic
			Cmd:    exec.Command(fmt.Sprintf("./build/plugin/%s", name)),
			Logger: pluginLogger,
		})
		// credPluginsClients[name] = client
		defer client.Kill()

		rpcClient, err := client.Client()
		if err != nil {
			panic(fmt.Sprintf("connect blew up: %s", err))
		}

		// Request the plugin
		raw, err := rpcClient.Dispense("vault")
		if err != nil {
			panic(fmt.Sprintf("dispense blew up: %s", err))
		}

		provider := raw.(credentials.Provider)
		credPluginsClients[name] = provider
	}

	// Any Argo Workflow client method calls need the context returned from NewAPIClient, otherwise
	// nil errors will occur. Mux sets its params in context, so passing the Argo Workflow context to
	// setupRouter and applying it to the request will wipe out Mux vars (or any other data Mux sets in its context).
	h := handler{
		logger:             logger,
		argo:               workflow.NewArgoWorkflow(argoClient.NewWorkflowServiceClient(), env.ArgoNamespace),
		argoCtx:            argoCtx,
		config:             config,
		gitClient:          gitClient(env, errLogger),
		env:                env,
		dbClient:           dbClient,
		credentialsPlugins: credPluginsClients,
	}

	level.Info(logger).Log("message", "starting web service", "vault addr", env.VaultAddress, "argoAddr", env.ArgoAddress)
	if err := http.ListenAndServeTLS(fmt.Sprintf(":%d", env.Port), "ssl/certificate.crt", "ssl/certificate.key", setupRouter(h)); err != nil {
		level.Error(errLogger).Log("message", "error starting service", "error", err)
		os.Exit(1)
	}
}

func setLogLevel(logger *log.Logger, logLevel string) {
	switch logLevel {
	case "DEBUG":
		*logger = level.NewFilter(*logger, level.AllowDebug())
	default:
		*logger = level.NewFilter(*logger, level.AllowInfo())
	}
}

func gitClient(env env.Vars, errLogger log.Logger) git.BasicClient {
	var cl git.BasicClient
	var err error

	var opts []git.Option
	if env.LogLevel == "DEBUG" {
		opts = append(opts, git.WithProgressWriter(os.Stdout))
	}

	if env.GitAuthMethod == "https" {
		cl, err = git.NewHTTPSBasicClient(env.GitHTTPSUser, env.GitHTTPSPass, opts...)
	} else if env.GitAuthMethod == "ssh" {
		cl, err = git.NewSSHBasicClient(env.SSHPEMFile, opts...)
	} else {
		panic(fmt.Sprintf("Invalid git auth method provided %s", env.GitAuthMethod))
	}

	if err != nil {
		level.Error(errLogger).Log("message", "error creating git client", "error", err)
		os.Exit(1)
	}

	return cl
}
