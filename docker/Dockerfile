FROM tommylike/signatrust-builder:0.0.2 as builder
ARG BINARY
LABEL Author=TommyLike<tommylikehu@gmail.com>
WORKDIR /app
COPY .. /app


RUN cargo build --release --bin $BINARY

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
COPY --from=builder --chown=$USER_UID:$USER_GID /app/target/release/$BINARY /app
COPY --chown=$USER_UID:$USER_GID $CONFIG /app/config/

ENTRYPOINT /app/$(echo $BINARY)
