#!/usr/bin/env bash

if [[ ! -v DATABASE_HOST ]]; then
    echo "DATABASE_HOST is not set"
    exit 1
elif [[ ! -v DATABASE_PORT ]]; then
    echo "DATABASE_PORT is not set"
    exit 1
elif [[ ! -v DATABASE_USER ]]; then
    echo "DATABASE_USER is not set"
    exit 1
elif [[ ! -v DATABASE_PASSWORD ]]; then
    echo "DATABASE_PASSWORD is not set"
    exit 1
elif [[ ! -v DATABASE_NAME ]]; then
    echo "DATABASE_NAME is not set"
    exit 1
elif [[ ! -d "/app/migrations" ]]; then
    echo "/app/migrations folder is not exist"
    exit 1
fi

export DATABASE_URL="mysql://${DATABASE_USER}:${DATABASE_PASSWORD}@${DATABASE_HOST}:${DATABASE_PORT}/${DATABASE_NAME}"

cd /app/ || exit 1
/app/bin/sqlx database create || exit 1
/app/bin/sqlx migrate run || exit 1
