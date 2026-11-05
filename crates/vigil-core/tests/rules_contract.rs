//! Contract: `rules/*.toml` must match the tables in `docs/03-trust-scoring.md` and parse strictly.

use std::collections::BTreeMap;

use vigil_core::rules::{
    EMBEDDED_DEFAULT, Kind, Lolbins, Publishers, RulePack, SystemProcesses, Verdict,
};

const DOC03: &str = include_str!("../../../docs/03-trust-scoring.md");
const SYSTEM_PROCESSES: &str = include_str!("../../../rules/system_processes.toml");
const LOLBINS: &str = include_str!("../../../rules/lolbins.toml");
const PUBLISHERS: &str = include_str!("../../../rules/publishers.toml");

#[derive(Debug)]
struct DocRow {
    name: String,
    cells: Vec<String>,
}

/// Rows of the §2 catalogue tables keyed by rule id (first cell looks like `SIG-001`).
fn doc_rows() -> BTreeMap<String, DocRow> {
    let section = DOC03
        .split("## 2. Signal catalogue")
        .nth(1)
        .and_then(|s| s.split("## 3.").next())
        .expect("docs/03 has section 2");
    section
        .lines()
        .filter(|l| l.starts_with("| "))
        .filter_map(|l| {
            let cells: Vec<String> = l
                .trim()
                .trim_matches('|')
                .split('|')
                .map(|c| c.trim().to_string())
                .collect();
            let id = cells.first()?.clone();
            let is_id = id.split_once('-').is_some_and(|(p, n)| {
                p.chars().all(|c| c.is_ascii_uppercase()) && n.chars().all(|c| c.is_ascii_digit())
            });
            is_id.then(|| {
                (
                    id,
                    DocRow {
                        name: cells[1].trim_matches('`').to_string(),
                        cells,
                    },
                )
            })
        })
        .collect()
}

fn parse_delta(cell: &str) -> i32 {
    cell.replace('\u{2212}', "-")
        .trim_start_matches('+')
        .parse()
        .expect("delta is an integer")
}

fn pack() -> RulePack {
    RulePack::parse("default.toml", EMBEDDED_DEFAULT).expect("default pack is valid")
}

#[test]
fn every_doc_rule_exists_in_pack_and_vice_versa() {
    let rows = doc_rows();
    let pack = pack();
    let doc_ids: Vec<_> = rows.keys().cloned().collect();
    let pack_ids: Vec<_> = {
        let mut v: Vec<_> = pack.rules.iter().map(|r| r.id.clone()).collect();
        v.sort();
        v
    };
    assert_eq!(
        doc_ids, pack_ids,
        "rule ids differ between docs/03 §2 and rules/default.toml"
    );
    assert_eq!(pack.rules.len(), 38);
}

#[test]
fn names_deltas_and_caps_match_the_doc_tables() {
    let rows = doc_rows();
    for rule in &pack().rules {
        let row = &rows[&rule.id];
        assert_eq!(rule.name, row.name, "{}: name", rule.id);
        if rule.kind == Kind::Signal {
            assert_eq!(
                row.cells.len(),
                5,
                "{}: signal rows have 5 columns",
                rule.id
            );
            assert_eq!(
                rule.score,
                Some(parse_delta(&row.cells[3])),
                "{}: delta",
                rule.id
            );
            let cap = (!row.cells[4].is_empty()).then(|| row.cells[4].parse::<u8>().unwrap());
            assert_eq!(rule.cap, cap, "{}: cap", rule.id);
        }
    }
}

#[test]
fn hard_rule_and_allow_results_match_the_doc() {
    let rows = doc_rows();
    for rule in &pack().rules {
        let result = rows[&rule.id].cells.last().unwrap().as_str();
        match rule.kind {
            Kind::HardRule => {
                assert_eq!(result, "malicious", "{}", rule.id);
                assert_eq!(rule.verdict, Some(Verdict::Malicious));
            }
            Kind::HardAllow => {
                assert_eq!(result, "safe", "{}", rule.id);
                assert_eq!(rule.verdict, Some(Verdict::Safe));
            }
            Kind::Guard => assert!(result.contains("blocks kill/deny"), "{}", rule.id),
            Kind::Signal => {}
        }
    }
}

#[test]
fn signer_trust_group_priorities_match_the_doc() {
    let pack = pack();
    let priority = |id: &str| pack.rule(id).and_then(|r| r.priority);
    assert_eq!(priority("SIG-001"), Some(3));
    assert_eq!(priority("SIG-002"), Some(2));
    assert_eq!(priority("SIG-003"), Some(1));
    assert!(DOC03.contains("SIG-001 = 3, SIG-002 = 2, SIG-003 = 1"));
}

#[test]
fn auxiliary_rule_files_parse_strictly() {
    let sys = SystemProcesses::parse("system_processes.toml", SYSTEM_PROCESSES).unwrap();
    assert!(
        sys.processes
            .iter()
            .any(|p| p.name == "svchost.exe" && p.never_kill)
    );
    let lol = Lolbins::parse("lolbins.toml", LOLBINS).unwrap();
    assert!(lol.lolbins.names.iter().any(|n| n == "powershell.exe"));
    let pubs = Publishers::parse("publishers.toml", PUBLISHERS).unwrap();
    assert!(pubs.publishers.iter().any(|p| p.id == "microsoft"));
}

#[test]
fn doc_hard_rule_ids_are_the_only_terminal_rules() {
    for rule in &pack().rules {
        assert_eq!(
            rule.terminal,
            matches!(rule.kind, Kind::HardRule | Kind::HardAllow),
            "{}",
            rule.id
        );
    }
}
