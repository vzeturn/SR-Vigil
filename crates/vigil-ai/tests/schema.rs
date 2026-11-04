//! `schemas/ai-verdict.schema.json` must be valid JSON Schema (2020-12).

#[test]
fn ai_verdict_schema_parses_and_compiles() {
    let text = include_str!("../../../schemas/ai-verdict.schema.json");
    let schema: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
    jsonschema::validator_for(&schema).expect("valid JSON Schema");
}
