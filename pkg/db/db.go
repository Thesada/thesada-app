// Package db wraps a pgx connection pool. Migrations are managed out-of-band
// via plain SQL files in migrations/ - apply with psql or any runner.
package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool is a type alias for pgxpool.Pool so callers don't need to import pgxpool directly.
type Pool = pgxpool.Pool

// Open creates a pgx connection pool with conservative defaults.
// in: ctx, postgres connection URL. out: ready *Pool or parse/connect error.
func Open(ctx context.Context, url string) (*Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 10
	cfg.MaxConnLifetime = time.Hour
	return pgxpool.NewWithConfig(ctx, cfg)
}

// Ping verifies the pool can reach the database with a 5s timeout.
// in: ctx (parent), pool. out: error if ping fails or times out.
func Ping(ctx context.Context, p *Pool) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return p.Ping(ctx)
}
