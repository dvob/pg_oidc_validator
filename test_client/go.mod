module test-client

go 1.25.1

replace github.com/jackc/pgx/v5 => github.com/dvob/pgx/v5 v5.0.0-20251012104547-644ea6b24fe3

require (
	github.com/coreos/go-oidc/v3 v3.16.0
	github.com/jackc/pgx/v5 v5.0.0-00010101000000-000000000000
	golang.org/x/oauth2 v0.32.0
)

require (
	github.com/go-jose/go-jose/v4 v4.1.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	golang.org/x/text v0.29.0 // indirect
)
