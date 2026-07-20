fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(
        &[
            "proto/sync.proto",
            "proto/shellipc.proto",
            "proto/local_discovery.proto",
            "proto/daemon_control.proto",
        ],
        &["proto"],
    )?;
    Ok(())
}
