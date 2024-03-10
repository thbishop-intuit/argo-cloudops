CREATE TABLE IF NOT EXISTS targets (
	created_at TIMESTAMPTZ NOT NULL,
	target_id VARCHAR(80) NOT NULL,
	project VARCHAR(80) NOT NULL,
	properties JSONB NOT NULL,
	type VARCHAR(80) NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT targets_pkey PRIMARY KEY(target_id, project),
    FOREIGN KEY (project) REFERENCES projects(project) on delete cascade on update cascade
);
GRANT ALL PRIVILEGES ON targets TO cello;
