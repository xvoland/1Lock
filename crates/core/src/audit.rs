//! Security audit: which passwords are weak, which are reused, which are stale.
//!
//! The counting lives here rather than in the UI: it depends on record parsing
//! and must be testable without a window. The current time is passed in as an
//! argument — otherwise "older than three years" would depend on the machine.

use std::collections::HashMap;

use crate::pif::Pif;

/// A password counts as stale once its record has not changed for this long.
pub const STALE_AFTER_YEARS: i64 = 3;

/// Password strength score: from 0 (empty) to 4 (very strong).
///
/// The scoring is deliberately crude and explainable: length plus the number of character classes.
/// Real entropy needs dictionaries, and there are none here — the point is not to pass a
/// rough heuristic off as the truth.
pub fn strength(password: &str) -> u8 {
    if password.is_empty() {
        return 0;
    }

    let len = password.chars().count();
    let classes = [
        password.chars().any(|c| c.is_ascii_lowercase()),
        password.chars().any(|c| c.is_ascii_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password
            .chars()
            .any(|c| !c.is_alphanumeric() && !c.is_whitespace()),
    ]
    .iter()
    .filter(|on| **on)
    .count();

    match (len, classes) {
        (_, 0) => 0,
        (len, 1) if len < 10 => 1,
        (_, 1) => 2,
        (len, 2) if len < 12 => 2,
        (_, 2) => 3,
        (len, _) if len < 16 => 3,
        _ => 4,
    }
}

/// Whether a password is weak.
pub fn is_weak(password: &str) -> bool {
    strength(password) <= 1
}

/// A record referred to by name.
#[derive(Debug)]
pub struct Ref {
    /// Record identifier: what gets selected in the list.
    pub uuid: String,
    /// Record title.
    pub title: String,
}

/// A group of records sharing one password.
pub struct ReuseGroup {
    /// The password itself. It only reaches the report if the group is
    /// non-empty and holds more than one record, but the text is a secret
    /// all the same: we hand out [`ReuseGroup::titles`] instead.
    pub password: String,
    /// Records using this password.
    pub entries: Vec<Ref>,
}

/// The password of a reuse group never reaches debug output: the struct is
/// secret, and `{:?}` gets called on it more often than you would think.
impl std::fmt::Debug for ReuseGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReuseGroup")
            .field("password", &"<hidden>")
            .field("entries", &self.entries)
            .finish()
    }
}

/// A record with a problematic password.
#[derive(Debug)]
pub struct Flagged {
    /// Record identifier: what gets selected in the list.
    pub uuid: String,
    /// Record title.
    pub title: String,
    /// How weak the password is, 0..=4.
    pub strength: u8,
}

/// Audit result over live records.
#[derive(Debug)]
pub struct AuditReport {
    /// How many records have a password at all.
    pub with_password: usize,
    /// How many distinct passwords there are among them.
    pub unique: usize,
    /// How many records reuse a password.
    pub reused: usize,
    /// How many records have a weak password.
    pub weak: usize,
    /// How many records have not changed for longer than [`STALE_AFTER_YEARS`].
    pub stale: usize,
    /// Groups of reused passwords, sorted by descending size.
    pub reuse_groups: Vec<ReuseGroup>,
    /// Records with weak passwords, sorted worst to best.
    pub weak_items: Vec<Flagged>,
    /// Records that have not been changed in a long time.
    pub stale_items: Vec<Flagged>,
}

/// Parses live records and assembles the report.
///
/// Deleted records are left out: in 1Password the audit likewise only looks at
/// what is actually in use. `now` is the time in seconds since the epoch.
pub fn run(pif: &Pif, now: i64) -> AuditReport {
    let mut by_password: HashMap<String, Vec<Ref>> = HashMap::new();
    let mut weak_items = Vec::new();
    let mut stale_items = Vec::new();

    let cutoff = now - STALE_AFTER_YEARS * 365 * 24 * 3600;

    for item in pif.alive() {
        let title = item
            .title
            .clone()
            .unwrap_or_else(|| "(untitled)".to_string());

        if let Some(password) = item.primary_password() {
            let score = strength(password);
            by_password
                .entry(password.to_string())
                .or_default()
                .push(Ref {
                    uuid: item.uuid.clone(),
                    title: title.clone(),
                });

            if is_weak(password) {
                weak_items.push(Flagged {
                    uuid: item.uuid.clone(),
                    title: title.clone(),
                    strength: score,
                });
            }
        }

        // No dates, or zeroed ones — the record is not counted as stale: a
        // missing datum is no reason to blame the user.
        if let Some(updated) = item.updated_at.filter(|v| *v > 0) {
            if updated < cutoff {
                stale_items.push(Flagged {
                    uuid: item.uuid.clone(),
                    title,
                    strength: item.primary_password().map_or(0, strength),
                });
            }
        }
    }

    let with_password: usize = by_password.values().map(Vec::len).sum();
    let unique = by_password.len();

    let mut reuse_groups: Vec<ReuseGroup> = by_password
        .into_iter()
        .filter(|(_, entries)| entries.len() > 1)
        .map(|(password, entries)| ReuseGroup { password, entries })
        .collect();
    // Most-reused first: those are the ones that need changing soonest.
    reuse_groups.sort_by(|a, b| {
        b.entries.len().cmp(&a.entries.len()).then_with(|| {
            a.entries
                .first()
                .map(|e| &e.title)
                .cmp(&b.entries.first().map(|e| &e.title))
        })
    });

    let reused: usize = reuse_groups.iter().map(|g| g.entries.len()).sum();

    weak_items.sort_by(|a, b| {
        a.strength
            .cmp(&b.strength)
            .then_with(|| a.title.cmp(&b.title))
    });
    stale_items.sort_by(|a, b| a.title.cmp(&b.title));

    AuditReport {
        with_password,
        unique,
        reused,
        weak: weak_items.len(),
        stale: stale_items.len(),
        reuse_groups,
        weak_items,
        stale_items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pif::Pif;

    const NOW: i64 = 1_700_000_000;

    /// A year in seconds, as 1Password counts unix time.
    const YEAR: i64 = 365 * 24 * 3600;

    fn doc(title: &str, password: &str, updated: i64) -> String {
        format!(
            r#"{{"uuid":"{}","typeName":"webforms.WebForm","title":"{title}","updatedAt":{updated},"createdAt":{updated},"secureContents":{{"fields":[{{"designation":"password","value":"{password}"}}]}}}}"#,
            crate::pif::new_uuid()
        )
    }

    fn pif_of(lines: &[String]) -> Pif {
        Pif::parse(&lines.join("\n")).unwrap()
    }

    #[test]
    fn empty_password_scores_weakest() {
        assert_eq!(strength(""), 0);
        assert!(is_weak(""));
    }

    #[test]
    fn short_password_is_weak() {
        assert_eq!(strength("abc"), 1);
        assert!(is_weak("abc"));
        assert!(is_weak("1234567"));
    }

    #[test]
    fn long_varied_password_is_strong() {
        assert!(!is_weak("Correct-Horse-9"));
        assert!(!is_weak("Правильный-Конь-Батарейка-9!"));
        assert_eq!(strength("Aa1!Aa1!Aa1!Aa1!"), 4);
    }

    #[test]
    fn length_beats_variety() {
        // Twenty-six letters in a row is still only one character class.
        assert_eq!(strength("abcdefghijklmnopqrstuvwxyz"), 2);
        assert!(!is_weak("abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn counts_reuse_weak_and_stale() {
        let lines = vec![
            doc("Github", "shared-secret", NOW - YEAR),
            doc("Gitlab", "shared-secret", NOW - 2 * YEAR),
            doc("Reddit", "another-one", NOW - 5 * YEAR),
            doc("Old", "Passw0rd!Passw0rd!", NOW - 9 * YEAR),
            doc("Short", "abc", NOW),
        ];
        let pif = pif_of(&lines);
        let report = run(&pif, NOW);

        assert_eq!(report.with_password, 5);
        assert_eq!(report.unique, 4, "two records share one password");
        assert_eq!(report.reused, 2, "records with a reused password");
        assert_eq!(report.weak, 1, "only \"Short\"");
        // Reddit (5 years) and "Old" (9 years); 1 and 2 years are still in range.
        assert_eq!(report.stale, 2, "older than three years");
    }

    #[test]
    fn trashed_records_are_ignored() {
        let mut lines = vec![doc("Live", "good-secret-1", NOW)];
        lines.push(format!(
            r#"{{"uuid":"{}","typeName":"webforms.WebForm","title":"Deleted","trashed":true,"secureContents":{{"fields":[{{"designation":"password","value":"bad"}}]}}}}"#,
            crate::pif::new_uuid()
        ));
        let pif = pif_of(&lines);

        let report = run(&pif, NOW);
        assert_eq!(report.with_password, 1);
        assert_eq!(report.weak, 0, "a deleted record is not counted as weak");
    }

    #[test]
    fn records_without_a_date_are_not_stale() {
        let line = r#"{"uuid":"U","typeName":"webforms.WebForm","title":"No date","secureContents":{"fields":[{"designation":"password","value":"good-secret-1"}]}}"#.to_string();
        let pif = pif_of(&[line]);

        let report = run(&pif, NOW);
        assert_eq!(report.stale, 0, "no data is no reason to blame anyone");
    }

    #[test]
    fn reuse_groups_come_most_frequent_first() {
        let mut lines = vec![doc("A1", "twice", NOW), doc("A2", "twice", NOW)];
        lines.push(doc("B1", "thrice", NOW));
        lines.push(doc("B2", "thrice", NOW));
        lines.push(doc("B3", "thrice", NOW));
        let pif = pif_of(&lines);

        let report = run(&pif, NOW);
        assert_eq!(report.reuse_groups.len(), 2);
        assert_eq!(
            report.reuse_groups[0].entries.len(),
            3,
            "the most frequent one comes first"
        );
        assert_eq!(report.reuse_groups[1].entries.len(), 2);
        // Records in a group have to be clickable: they carry both a uuid and a title.
        assert!(!report.reuse_groups[0].entries[0].uuid.is_empty());
    }

    #[test]
    fn empty_vault_gives_zeros() {
        let pif =
            Pif::create(std::env::temp_dir().join(format!("audit-empty-{}", std::process::id())))
                .unwrap();
        let report = run(&pif, NOW);

        assert_eq!(report.with_password, 0);
        assert_eq!(report.unique, 0);
        assert_eq!(report.reused, 0);
        assert_eq!(report.weak, 0);
        assert_eq!(report.stale, 0);
        assert!(report.reuse_groups.is_empty());

        let _ = std::fs::remove_dir_all(pif.source_path.unwrap().parent().unwrap());
    }
}
