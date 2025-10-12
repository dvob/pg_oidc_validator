# Postgres OAuth Validator Module using OIDC

This repo contains a OAuth validator module which uses OIDC discovery and JWKS to validate JWT tokens.
I implemented this to test if one could use Kubernetes service accounts for authentication with Postgres.

```
kind create cluster
kubectl apply -f k8s/
```
