#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

export CURRENT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/..
export REDIS_IMAGE="redis:7.2-rc-alpine"
export REDIS_PASSWORD="signatrust-redis"

function check-prerequisites {
  echo "checking prerequisites"
  which docker >/dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    echo "docker not installed, exiting."
    exit 1
  else
    echo -n "found docker, " && docker version
  fi

}

function redis-cluster-up {
  echo "running up redis local cluster"
  docker rm signatrust-redis --force
  docker run --name signatrust-redis --rm -p 6379:6379 --entrypoint "/usr/local/bin/redis-server" -d ${REDIS_IMAGE} --requirepass ${REDIS_PASSWORD}
  echo "redis is running up with ip address $(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' signatrust-redis)"
  echo "waiting redis to be ready"
  sleep 5
  echo "redis is ready, use password ${REDIS_PASSWORD} for connection"
}

echo "Preparing redis environment for signatrust developing......"

check-prerequisites

redis-cluster-up