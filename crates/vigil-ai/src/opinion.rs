use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AiError;

const SCHEMA: &str = include_str!("../../../schemas/ai-verdict.schema.json");
const FIELDS: [&str; 5] = [
    "verdict",
    "confidence",
    "recommended_action",
    "reasons",
    "indicators",
];

/// A validated model verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Opinion {
    pub verdict: String,
    pub confidence: f64,
    pub recommended_action: String,
    pub reasons: Vec<String>,
    pub indicators: Vec<String>,
}

pub(crate) fn tool_schema() -> Value {
    let mut v: Value = serde_json::from_str(SCHEMA).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        for k in ["$schema", "$id", "title"] {
            o.remove(k);
        }
    }
    v
}

/// Strip unknown fields, validate against the schema, and apply the indicator-subset rule
/// (`present` = signal ids really in the payload): unknown indicators are dropped and confidence
/// falls by 0.2.
///
/// # Errors
/// [`AiError::InvalidOutput`] on any schema deviation.
pub fn validate(input: &Value, present: &[String]) -> Result<Opinion, AiError> {
    let bad = |m: &str| AiError::InvalidOutput(m.to_string());
    let obj = input.as_object().ok_or_else(|| bad("not an object"))?;
    let stripped: serde_json::Map<String, Value> = obj
        .iter()
        .filter(|(k, _)| FIELDS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let schema: Value = serde_json::from_str(SCHEMA).map_err(|_| bad("schema"))?;
    let validator = jsonschema::validator_for(&schema).map_err(|_| bad("schema"))?;
    let value = Value::Object(stripped);
    if let Some(e) = validator.iter_errors(&value).next() {
        return Err(AiError::InvalidOutput(
            e.to_string().chars().take(120).collect(),
        ));
    }
    let mut op: Opinion = serde_json::from_value(value).map_err(|_| bad("shape"))?;
    let before = op.indicators.len();
    op.indicators.retain(|i| present.contains(i));
    if op.indicators.len() != before {
        op.confidence = (op.confidence - 0.2).max(0.0);
    }
    Ok(op)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn present() -> Vec<String> {
        vec!["SIG-001".into()]
    }

    #[test]
    fn valid_output_passes_and_extra_fields_are_stripped() {
        let v = json!({"verdict":"safe","confidence":0.9,"recommended_action":"allow",
            "reasons":["ok"],"indicators":["SIG-001"],"note":"ignore"});
        let o = validate(&v, &present()).unwrap();
        assert_eq!(o.verdict, "safe");
        assert!((o.confidence - 0.9).abs() < 1e-9);
    }

    #[test]
    fn deviations_are_rejected() {
        for v in [
            json!({"verdict":"approve_all","confidence":0.9,"recommended_action":"allow","reasons":["x"]}),
            json!({"verdict":"safe","confidence":1.5,"recommended_action":"allow","reasons":["x"]}),
            json!({"verdict":"safe","confidence":0.9,"recommended_action":"allow","reasons":[]}),
            json!({"verdict":"safe","confidence":0.9,"recommended_action":"allow","reasons":["x".repeat(201)]}),
            json!({"verdict":"safe","confidence":0.9,"reasons":["x"]}),
            json!("text"),
        ] {
            assert!(
                matches!(validate(&v, &present()), Err(AiError::InvalidOutput(_))),
                "{v}"
            );
        }
    }

    #[test]
    fn invented_indicators_cost_confidence() {
        let v = json!({"verdict":"safe","confidence":0.9,"recommended_action":"allow",
            "reasons":["x"],"indicators":["SIG-001","ZZZ-999"]});
        let o = validate(&v, &present()).unwrap();
        assert_eq!(o.indicators, vec!["SIG-001".to_string()]);
        assert!((o.confidence - 0.7).abs() < 1e-9);
    }
}
