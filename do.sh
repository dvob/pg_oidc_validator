#!/bin/sh

do_install() {
	cargo build --release && install -v -m 755 target/release/liboidc_validator.so $(pg_config --pkglibdir)/oidc_validator.so
}

do_docker-build() {
	docker build -t dvob/postgres-oidc .
}

do_docker-run() {
	if [ -z "$ISSUER_URL" ] 
	then
		echo "ISSUER_URL not set" >&2
		exit 2
	fi

	docker run -it --rm \
	  --name postgres-oidc \
	  -p 5432:5432 \
	  -e POSTGRES_USER=${POSTGRES_USER:-app} \
	  -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-apppw} \
	  -e POSTGRES_DB=${POSTGRES_DB:-app} \
	  -e "POSTGRES_HOST_AUTH_METHOD=oauth validator=oidc_validator issuer=$ISSUER_URL scope=" \
	  -e ISSUER_URL \
	  dvob/postgres-oidc \
	  -c oauth_validator_libraries='oidc_validator'
}

if ! type do_"$1" >/dev/null 2>&1; then
        echo "task '$1' does not exist" >&2
        exit 1
fi

cmd=$1
shift
do_$cmd "$@"


