#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

function check-binary {
  echo "checking control-admin binary"
  which ./target/debug/control-admin >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    echo "control-admin binary not found, please use command 'cargo build --bin control-admin' to build it first, exiting."
    exit 1
  else
    echo -n "found control-admin binary, " && docker version
  fi
}

function create_default_admin {
  echo "start to create default admin with tommylikehu@gmail.com"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml create-admin --email tommylikehu@gmail.com
}

function create_default_openpgp_keys {
  echo "start to create default openpgp keys identified with default-pgp"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-pgp --description "used for test purpose only" --key-type pgp --email tommylikehu@gmail.com --param-key-type rsa --param-key-size 2048
}

echo "Preparing basic keys for signatrust......"

check-binary

echo "==========================================="

create_default_admin

create_default_openpgp_keys