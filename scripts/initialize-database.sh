#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

export CURRENT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/..
export MYSQL_IMAGE="mysql:8.0"
export MYSQL_DATABASE="signatrust"
export MYSQL_PASSWORD="test"
export MYSQL_USER="test"

function check-prerequisites {
  echo "checking prerequisites"
  which docker >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    echo "docker not installed, exiting."
    exit 1
  else
    echo -n "found docker, " && docker version
  fi

  echo "checking mysql"
    which mysql >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      echo "mysql not installed, exiting."
      exit 1
    else
      echo -n "found mysql, " && mysql --version
    fi
  echo "checking sqlx"
    which sqlx >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
      echo "sqlx not installed, please refer to https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md#enable-building-in-offline-mode-with-query for installing, exiting."
      exit 1
    else
      echo -n "found sqlx, " && sqlx --version
    fi
}

function mysql-cluster-up {
  echo "running up mysql local cluster"
  docker rm signatrust-database --force
  docker run --name signatrust-database --rm -p 3306:3306 -e MYSQL_DATABASE=${MYSQL_DATABASE} -e MYSQL_PASSWORD=${MYSQL_PASSWORD} -e MYSQL_USER=${MYSQL_USER} -e MYSQL_ROOT_PASSWORD=root -d ${MYSQL_IMAGE}
  echo "mysql is running up with ip address $(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' signatrust-database)"
  echo "waiting mysql to be ready"
  while ! mysql --user=${MYSQL_USER} --password=${MYSQL_PASSWORD} --host=127.0.0.1  -e "select 1;"; do
      sleep 3
  done
  echo "mysql is ready"
  echo "Please use command mysql --user=${MYSQL_USER} --password=${MYSQL_PASSWORD} --host=127.0.0.1 to query database"
}

function prepare-database {
  echo "running database migrations"
  export DATABASE_URL=mysql://${MYSQL_USER}:${MYSQL_PASSWORD}@127.0.0.1/${MYSQL_DATABASE}
  sqlx database create
  sqlx migrate run
}

echo "Preparing mysql  environment for signatrust developing......"

check-prerequisites

mysql-cluster-up

prepare-database