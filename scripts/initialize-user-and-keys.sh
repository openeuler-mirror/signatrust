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

function create_default_x509_ca {
  echo "start to create default x509 CA identified with default-x509"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-x509ca --description "used for test purpose only" --key-type x509ca --email tommylikehu@gmail.com --param-key-type rsa --param-key-size 2048 \
  --param-x509-common-name Infra --param-x509-organization Huawei --param-x509-locality ShenZhen --param-x509-province-name GuangDong --param-x509-country-name CN --param-x509-organizational-unit Infra --digest-algorithm sha2_256
}

function create_default_x509_ica {
  echo "start to create default x509 ICA identified with default-x509"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-x509ica --description "used for test purpose only" --key-type x509ica --email tommylikehu@gmail.com --param-key-type rsa --param-key-size 2048 \
  --param-x509-common-name Infra --param-x509-organization Huawei --param-x509-locality ShenZhen --param-x509-province-name GuangDong --param-x509-country-name CN --param-x509-organizational-unit Infra --digest-algorithm sha2_256 --param-x509-parent-name default-x509ca
}

function create_default_x509_ee {
  echo "start to create default x509 EE certificate identified with default-x509"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-x509ee --description "used for test purpose only" --key-type x509ee --email tommylikehu@gmail.com --param-key-type rsa --param-key-size 2048 \
  --param-x509-common-name Infra --param-x509-organization Huawei --param-x509-locality ShenZhen --param-x509-province-name GuangDong --param-x509-country-name CN --param-x509-organizational-unit Infra --digest-algorithm sha2_256 --param-x509-parent-name default-x509ica
}

function create_default_openpgp_keys {
  echo "start to create default openpgp keys identified with default-pgp"
  RUST_LOG=info ./target/debug/control-admin --config ./config/server.toml generate-keys --name default-pgp --description "used for test purpose only" --key-type pgp --email tommylikehu@gmail.com --param-key-type rsa --param-key-size 2048 --param-pgp-email infra@openeuler.org --param-pgp-passphrase husheng1234 --digest-algorithm sha2_256
}


echo "Preparing basic keys for signatrust......"

check-binary

echo "==========================================="

create_default_admin

create_default_x509_ca

create_default_x509_ica

create_default_x509_ee

create_default_openpgp_keys

