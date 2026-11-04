//! `schemas/ipc.schema.json` must be valid JSON Schema (2020-12).

#[test]
fn ipc_schema_parses_and_compiles() {
    let text = include_str!("../../../schemas/ipc.schema.json");
    let schema: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
    jsonschema::validator_for(&schema).expect("valid JSON Schema");
}
