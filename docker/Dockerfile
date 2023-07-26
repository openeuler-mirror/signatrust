FROM clux/muslrust:nightly as builder
ARG BINARY
LABEL Author=TommyLike<tommylikehu@gmail.com>
WORKDIR /app
COPY .. /app


RUN cargo +nightly build --release --bin $BINARY --target x86_64-unknown-linux-musl

#The sql-cli@0.7.1 binary is pre-build with dockerfile `Dockerfile.sqlx-cli`.
FROM tommylike/sqlx-cli:0.7.1 as sqlx-cli

FROM openeuler/openeuler:22.03
ARG USERNAME=signatrust
ARG USER_UID=1000
ARG USER_GID=$USER_UID

ARG BINARY
ARG CONFIG=./config
ENV BINARY=${BINARY}

RUN yum install -y shadow && groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

USER $USERNAME
WORKDIR /app
COPY --from=builder --chown=$USER_UID:$USER_GID /app/target/x86_64-unknown-linux-musl/release/$BINARY /app
COPY --from=sqlx-cli --chown=$USER_UID:$USER_GID /app/bin/sqlx /app
COPY --chown=$USER_UID:$USER_GID $CONFIG /app/config/
COPY --chown=$USER_UID:$USER_GID ../migrations /app/migrations

ENTRYPOINT /app/$(echo $BINARY)
