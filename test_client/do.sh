#!/bin/sh

do_docker-build() {
	docker build -t dvob/postgres-oidc-client .
}

if ! type do_"$1" >/dev/null 2>&1; then
        echo "task '$1' does not exist" >&2
        exit 1
fi

cmd=$1
shift
do_$cmd "$@"


