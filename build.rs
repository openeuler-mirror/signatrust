fn main() {
    tonic_build::compile_protos("proto/signatrust.proto").unwrap();
    tonic_build::compile_protos("proto/health.proto").unwrap();
}
