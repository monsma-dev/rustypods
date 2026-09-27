//! Contract test: the Apotheek Centraal stack.toml must stay valid
//! against the real stack parser + HA admission rules. Dogfooding —
//! the file lives in the deploy repo and is the actual deploy unit.

#[test]
fn apotheek_stack_parses_and_passes_admission() {
    let toml = include_str!("/home/nick/Projects/apotheekcentraal/deploy/stack.toml");
    // Images are placeholders pending import — accept every name.
    let def = rustypodsd::stack::parse(toml, |_| true)
        .expect("deploy/stack.toml must parse + pass ha::admit");

    let mysql = &def.pods["mysql"];
    assert_eq!(mysql.ha, rustypodsd::ha::HaMode::Pinned);
    assert_eq!(mysql.replicates, rustypodsd::ha::Replication::Snapshot);
    assert!(mysql.volumes.iter().any(|v| v.starts_with("mysql-data:")));

    // Every served name has exactly one primary (parser-enforced) and
    // kernel + web are the published surface.
    assert_eq!(
        def.pods["kernel"].serves.as_deref(),
        Some("kernel.apotheek")
    );
    assert!(def.pods["kernel"].primary);
    assert_eq!(def.pods["web"].serves.as_deref(), Some("web.apotheek"));
}
