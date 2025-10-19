# Postgres OAuth Validator Module using OIDC

This repo contains a OAuth validator module which uses OIDC discovery and JWKS to validate JWT tokens.
I implemented this to test if one could use Kubernetes service accounts for authentication with Postgres.

## Install and Run

```bash
# you need pg_config of your Postgres installation in the path
export PATH=$PATH:$HOME/pg/pg18/bin

# Install and start
./do.sh install

# Initialize database
initdb -D tmp/mytest

# Configure PostgreSQL with validator
echo "shared_preload_libraries = 'oidc_validator'" >> tmp/mytest/postgresql.conf
echo "pg_oidc_validator.issuer_url = 'https://your-oidc-provider.com'" >> tmp/mytest/postgresql.conf
echo "log_connections = all" >> tmp/mytest/postgresql.conf

# Configure OAuth authentication in pg_hba.conf
echo "host    all    all    all    oauth    validator=oidc_validator issuer=https://your-oidc-provider.com scope=" >> tmp/mytest/pg_hba.conf

# Option 1: Foreground with logs (recommended for development)
postgres -D tmp/mytest

# Option 2: Background daemon
pg_ctl -D tmp/mytest -l tmp/mytest.log start

# Create user and database
psql -d postgres -c "CREATE USER myuser;"
psql -d postgres -c "CREATE DATABASE mydb OWNER myuser;"
```

## Client Test

In directory `test_client`.

`.env`:
```
export CLIENT_ID="postgres"
export CLIENT_SECRET="topsecret"
export ISSUER_URL="https://your-oidc-provider.com"
export CONN="host=127.0.0.1 port=5432 dbname=mydb user=AS-RETURNED-FROM-CLAIM-sub"
```

Make sure you have the appropriate database and user on your instance.

```
go run .
```

## Kubernetes Test
Build appropriate server and client:
```
./do.sh docker-build
( cd test_client && ./do.sh docker-build )

docker push dvob/postgres-oidc
docker push dvob/postgres-oidc-client
```

```bash
kind create cluster
kubectl apply -f k8s/
```
