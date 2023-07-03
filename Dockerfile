FROM clux/muslrust:nightly as builder
ARG BINARY
LABEL Author=TommyLike<tommylikehu@gmail.com>
WORKDIR /app
COPY . /app

RUN cargo +nightly build --release --bin $BINARY --target x86_64-unknown-linux-musl

FROM openeuler/openeuler:22.03
ARG BINARY
ENV BINARY=${BINARY}
WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/$BINARY /app
COPY ./config /app/config
COPY ./migrations /app/migrations
ENTRYPOINT ["/app/$(echo ${BINARY})"]
