fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile_protos(
        &[
            "proto/coordination.proto",
            "proto/sync.proto",
            "proto/shellipc.proto",
            "proto/relay.proto",
            "proto/local_discovery.proto",
            "proto/daemon_control.proto",
        ],
        &["proto"],
    )?;
    Ok(())
}
