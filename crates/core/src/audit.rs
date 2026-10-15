//! Аудит безопасности: какие пароли слабые, какие повторяются, какие устарели.
//!
//! Подсчёт живёт здесь, а не в интерфейсе: он опирается на разбор записи и
//! должен проверяться тестами без окна. Текущее время передаётся аргументом —
//! иначе «старше трёх лет» зависело бы от машины, на которой падают тесты.

use std::collections::HashMap;

use crate::pif::Pif;

/// Пароль считается устаревшим, если запись не менялась дольше этого срока.
pub const STALE_AFTER_YEARS: i64 = 3;

/// Оценка стойкости пароля: от 0 (пусто) до 4 (очень надёжно).
///
/// Оценка намеренно простая и объяснимая: длина плюс число классов символов.
/// Настоящая энтропия требует словарей, а их здесь нет — важно не выдавать
/// грубую эвристику за истину.
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

/// Слабый ли пароль.
pub fn is_weak(password: &str) -> bool {
    strength(password) <= 1
}

/// Запись, названная по имени.
#[derive(Debug)]
pub struct Ref {
    /// Идентификатор записи: по нему выбирается в списке.
    pub uuid: String,
    /// Название записи.
    pub title: String,
}

/// Группа записей, делящих один пароль.
pub struct ReuseGroup {
    /// Сам пароль. В отчёт попадает только если группа непустая и содержит
    /// больше одной записи, но текст всё равно секретный: наружу его не
    /// отдаём, наружу отдаём [`ReuseGroup::titles`].
    pub password: String,
    /// Записи с этим паролем.
    pub entries: Vec<Ref>,
}

/// Пароль из группы повторов в отладочный вывод не попадает: структура
/// секретная, а `{:?}` на ней вызывается чаще, чем кажется.
impl std::fmt::Debug for ReuseGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReuseGroup")
            .field("password", &"<hidden>")
            .field("entries", &self.entries)
            .finish()
    }
}

/// Запись с проблемным паролем.
#[derive(Debug)]
pub struct Flagged {
    /// Идентификатор записи: по нему выбирается в списке.
    pub uuid: String,
    /// Название записи.
    pub title: String,
    /// Насколько слабый пароль, 0..=4.
    pub strength: u8,
}

/// Итог аудита по живым записям.
#[derive(Debug)]
pub struct AuditReport {
    /// Сколько записей вообще имеют пароль.
    pub with_password: usize,
    /// Сколько разных паролей среди них.
    pub unique: usize,
    /// Сколько записей используют пароль повторно.
    pub reused: usize,
    /// Сколько записей со слабым паролем.
    pub weak: usize,
    /// Сколько записей не менялись дольше [`STALE_AFTER_YEARS`].
    pub stale: usize,
    /// Группы повторяющихся паролей, отсортированные по убыванию размера.
    pub reuse_groups: Vec<ReuseGroup>,
    /// Записи со слабыми паролями, отсортированные от худших к лучшим.
    pub weak_items: Vec<Flagged>,
    /// Записи, которые давно не меняли.
    pub stale_items: Vec<Flagged>,
}

/// Разбирает живые записи и собирает отчёт.
///
/// Удалённые записи не учитываются: в 1Password аудит тоже смотрит только на
/// то, чем пользуются. `now` — время в секундах с начала эпохи.
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

        // Дат нет или они нулевые — запись не считается старой: отсутствие
        // данных не повод обвинять пользователя.
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
    // Сначала самые часто повторяющиеся: их и надо менять в первую очередь.
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

    /// Год в секундах, как принято для unix-времени 1Password.
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
    fn пустой_пароль_самым_слабым() {
        assert_eq!(strength(""), 0);
        assert!(is_weak(""));
    }

    #[test]
    fn короткий_пароль_слабый() {
        assert_eq!(strength("abc"), 1);
        assert!(is_weak("abc"));
        assert!(is_weak("1234567"));
    }

    #[test]
    fn длинный_разнообразный_пароль_надёжен() {
        assert!(!is_weak("Correct-Horse-9"));
        assert!(!is_weak("Правильный-Конь-Батарейка-9!"));
        assert_eq!(strength("Aa1!Aa1!Aa1!Aa1!"), 4);
    }

    #[test]
    fn длина_важнее_разнообразия() {
        // Двадцать шесть букв подряд — это всё ещё один класс символов.
        assert_eq!(strength("abcdefghijklmnopqrstuvwxyz"), 2);
        assert!(!is_weak("abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn считает_повторы_слабые_и_старые() {
        let lines = vec![
            doc("Github", "shared-secret", NOW - YEAR),
            doc("Gitlab", "shared-secret", NOW - 2 * YEAR),
            doc("Reddit", "another-one", NOW - 5 * YEAR),
            doc("Старая", "Passw0rd!Passw0rd!", NOW - 9 * YEAR),
            doc("Короткая", "abc", NOW),
        ];
        let pif = pif_of(&lines);
        let report = run(&pif, NOW);

        assert_eq!(report.with_password, 5);
        assert_eq!(report.unique, 4, "два записей делят один пароль");
        assert_eq!(report.reused, 2, "повторно использованных записей");
        assert_eq!(report.weak, 1, "только «Короткая»");
        // Reddit (5 лет) и «Старая» (9 лет); year и 2 года ещё в пределах.
        assert_eq!(report.stale, 2, "старше трёх лет");
    }

    #[test]
    fn удалённые_записи_в_аудит_не_попадают() {
        let mut lines = vec![doc("Живая", "good-secret-1", NOW)];
        lines.push(format!(
            r#"{{"uuid":"{}","typeName":"webforms.WebForm","title":"Удалённая","trashed":true,"secureContents":{{"fields":[{{"designation":"password","value":"bad"}}]}}}}"#,
            crate::pif::new_uuid()
        ));
        let pif = pif_of(&lines);

        let report = run(&pif, NOW);
        assert_eq!(report.with_password, 1);
        assert_eq!(report.weak, 0, "удалённая запись не считается слабой");
    }

    #[test]
    fn записи_без_даты_не_считаются_старыми() {
        let line = r#"{"uuid":"U","typeName":"webforms.WebForm","title":"Без даты","secureContents":{"fields":[{"designation":"password","value":"good-secret-1"}]}}"#.to_string();
        let pif = pif_of(&[line]);

        let report = run(&pif, NOW);
        assert_eq!(report.stale, 0, "нет данных — не повод обвинять");
    }

    #[test]
    fn группы_повторов_идут_от_самых_частых() {
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
            "первой идёт самая частая"
        );
        assert_eq!(report.reuse_groups[1].entries.len(), 2);
        // Записи в группе кликабельны: у них есть и uuid, и название.
        assert!(!report.reuse_groups[0].entries[0].uuid.is_empty());
    }

    #[test]
    fn пустое_хранилище_даёт_нули() {
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
