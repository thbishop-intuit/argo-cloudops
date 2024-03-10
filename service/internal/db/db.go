//go:generate moq -out ../../test/testhelpers/dbClientMock.go -pkg testhelpers . Client:DBClientMock

package db

import (
	"context"
	"time"

	"github.com/cello-proj/cello/internal/types"

	"github.com/upper/db/v4"
	"github.com/upper/db/v4/adapter/postgresql"
)

type ProjectEntry struct {
	ProjectID  string `db:"project"`
	Repository string `db:"repository"`
}

type TokenEntry struct {
	CreatedAt string `db:"created_at"`
	ExpiresAt string `db:"expires_at"`
	ProjectID string `db:"project"`
	TokenID   string `db:"token_id"`
}

type TargetEntry struct {
	CreatedAt  string           `db:"created_at"`
	TargetID   string           `db:"target_id"`
	ProjectID  string           `db:"project"`
	Properties postgresql.JSONB `db:"properties"`
	Type       string           `db:"type"`
	UpdatedAt  string           `db:"updated_at"`
}

// IsEmpty returns whether a struct is empty.
func (t TokenEntry) IsEmpty() bool {
	return t == (TokenEntry{})
}

// Client allows for db crud operations
type Client interface {
	CreateProjectEntry(ctx context.Context, pe ProjectEntry) error
	DeleteProjectEntry(ctx context.Context, project string) error
	ReadProjectEntry(ctx context.Context, project string) (ProjectEntry, error)
	CreateTokenEntry(ctx context.Context, token types.Token) error
	DeleteTokenEntry(ctx context.Context, token string) error
	ReadTokenEntry(ctx context.Context, token string) (TokenEntry, error)
	ListTokenEntries(ctx context.Context, project string) ([]TokenEntry, error)
	CreateTargetEntry(ctx context.Context, project string, entry types.Target) error
	DeleteTargetEntry(ctx context.Context, project, target string) error
	ListTargetEntries(ctx context.Context, project string) ([]TargetEntry, error)
	ReadTargetEntry(ctx context.Context, project, target string) (TargetEntry, error)
	UpdateTargetEntry(ctx context.Context, project string, entry types.Target) error
	Health(ctx context.Context) error
}

// SQLClient allows for db crud operations using postgres db
type SQLClient struct {
	host     string
	database string
	user     string
	password string
}

const (
	ProjectEntryDB = "projects"
	TargetEntryDB  = "targets"
	TokenEntryDB   = "tokens"
)

func NewSQLClient(host, database, user, password string) (SQLClient, error) {
	return SQLClient{
		host:     host,
		database: database,
		user:     user,
		password: password,
	}, nil
}

func (d SQLClient) createSession() (db.Session, error) {
	settings := postgresql.ConnectionURL{
		Host:     d.host,
		Database: d.database,
		User:     d.user,
		Password: d.password,
	}

	return postgresql.Open(settings)
}

func (d SQLClient) Health(ctx context.Context) error {
	sess, err := d.createSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	return sess.WithContext(ctx).Ping()
}

func (d SQLClient) CreateProjectEntry(ctx context.Context, pe ProjectEntry) error {
	sess, err := d.createSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	return sess.WithContext(ctx).Tx(func(sess db.Session) error {
		if err := sess.Collection(ProjectEntryDB).Find("project", pe.ProjectID).Delete(); err != nil {
			return err
		}

		if _, err = sess.Collection(ProjectEntryDB).Insert(pe); err != nil {
			return err
		}

		return nil
	})
}

func (d SQLClient) ReadProjectEntry(ctx context.Context, project string) (ProjectEntry, error) {
	res := ProjectEntry{}

	sess, err := d.createSession()
	if err != nil {
		return res, err
	}
	defer sess.Close()

	err = sess.WithContext(ctx).Collection(ProjectEntryDB).Find("project", project).One(&res)
	return res, err
}

func (d SQLClient) DeleteProjectEntry(ctx context.Context, project string) error {
	sess, err := d.createSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	return sess.WithContext(ctx).Collection(ProjectEntryDB).Find("project", project).Delete()
}

func (d SQLClient) CreateTargetEntry(ctx context.Context, project string, target types.Target) error {
	sess, err := d.createSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	err = sess.WithContext(ctx).Tx(func(sess db.Session) error {
		now := time.Now().UTC().Format(time.RFC3339Nano)

		res := TargetEntry{
			CreatedAt:  now,
			TargetID:   target.Name,
			ProjectID:  project,
			Properties: postgresql.JSONB{V: target.Properties},
			Type:       target.Type,
			UpdatedAt:  now,
		}

		if _, err = sess.Collection(TargetEntryDB).Insert(res); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (d SQLClient) DeleteTargetEntry(ctx context.Context, project, target string) error {
	sess, err := d.createSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	return sess.WithContext(ctx).Collection(TargetEntryDB).Find("project", project, "target_id", target).Delete()
}

func (d SQLClient) ListTargetEntries(ctx context.Context, project string) ([]TargetEntry, error) {
	res := []TargetEntry{}

	sess, err := d.createSession()
	if err != nil {
		return res, err
	}
	defer sess.Close()

	err = sess.WithContext(ctx).Collection(TargetEntryDB).Find("project", project).OrderBy("-created_at").All(&res)
	// TODO need to process properties?
	return res, err
}

func (d SQLClient) ReadTargetEntry(ctx context.Context, project, target string) (TargetEntry, error) {
	res := TargetEntry{}
	sess, err := d.createSession()
	if err != nil {
		return res, err
	}
	defer sess.Close()

	err = sess.WithContext(ctx).Collection(TargetEntryDB).Find("project", project, "target_id", target).One(&res)
	// TODO process properties?
	return res, err
}

func (d SQLClient) UpdateTargetEntry(ctx context.Context, project string, target types.Target) error {
	sess, err := d.createSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)

	res := TargetEntry{
		TargetID:   target.Name,
		ProjectID:  project,
		Properties: postgresql.JSONB{V: target.Properties},
		Type:       target.Type,
		UpdatedAt:  now,
	}
	// TODO need to process properties?
	return sess.WithContext(ctx).Collection(TargetEntryDB).UpdateReturning(res)
}

func (d SQLClient) CreateTokenEntry(ctx context.Context, token types.Token) error {
	sess, err := d.createSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	err = sess.WithContext(ctx).Tx(func(sess db.Session) error {
		res := TokenEntry{
			CreatedAt: token.CreatedAt,
			ExpiresAt: token.ExpiresAt,
			ProjectID: token.ProjectID,
			TokenID:   token.ProjectToken.ID,
		}

		if _, err = sess.Collection(TokenEntryDB).Insert(res); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (d SQLClient) DeleteTokenEntry(ctx context.Context, token string) error {
	sess, err := d.createSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	return sess.WithContext(ctx).Collection(TokenEntryDB).Find("token_id", token).Delete()
}

func (d SQLClient) ReadTokenEntry(ctx context.Context, token string) (TokenEntry, error) {
	res := TokenEntry{}
	sess, err := d.createSession()
	if err != nil {
		return res, err
	}
	defer sess.Close()

	err = sess.WithContext(ctx).Collection(TokenEntryDB).Find("token_id", token).One(&res)
	return res, err
}

func (d SQLClient) ListTokenEntries(ctx context.Context, project string) ([]TokenEntry, error) {
	res := []TokenEntry{}

	sess, err := d.createSession()
	if err != nil {
		return res, err
	}
	defer sess.Close()

	err = sess.WithContext(ctx).Collection(TokenEntryDB).Find("project", project).OrderBy("-created_at").All(&res)
	return res, err
}
