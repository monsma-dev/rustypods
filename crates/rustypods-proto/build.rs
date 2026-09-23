fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // Serialize messages as proto-JSON (camelCase) so Tauri can return
        // them verbatim; the GUI parses with ts-proto's fromJSON.
        .type_attribute(
            ".",
            "#[derive(serde::Serialize)] #[serde(rename_all = \"camelCase\")]",
        )
        // HealthCheck is accepted verbatim in REST bodies too — type
        // attributes are additive, so the "." rename_all already applies;
        // only the extra derive is needed here.
        .type_attribute(
            "rustypods.v1.HealthCheck",
            "#[derive(serde::Deserialize)]",
        )
        .compile_protos(&["proto/rustypods.proto"], &["proto"])?;
    Ok(())
}
