fn main() {
    let sign_proto = "./proto/signatrust.proto";
    let health_proto = "./proto/health.proto";
    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(&[sign_proto, health_proto], &["proto"])
        .unwrap();
}
