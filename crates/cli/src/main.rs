//! CLI чтения бэкапа 1Password.
//!
//! Подкоманды:
//! - `info <db>` — сводка и статус KDF
//! - `folders <db>` — список папок (uuid + геометрия блоба)
//! - `items <db>` — список элементов (uuid, категория, папка, время)
//! - `inspect-key <db> <uuid>` — разбор `key_data` одного элемента
//! - `verify <db> <key-hex>` — массовая проверка HMAC заданным ключом
//!
//! Ключ нигде не читается из аргументов командной строки в открытом виде,
//! если он дан в hex — это осознанно: аргументы видны в `ps` и в истории.

use std::path::Path;
use std::process::ExitCode;

use opclient_core::{kdf, keys::Unavailable, Error, KeyProvider, Vault, KEY_LEN};

const USAGE: &str = "\
opclient — чтение бэкапа 1Password (.1p4), только чтение

ИСПОЛЬЗОВАНИЕ
  opclient <команда> <путь-к-OnePassword.sqlite> [аргументы]

КОМАНДЫ
  info <db>                 сводка: профиль, счётчики, SHA-256 базы, статус KDF
  folders <db>              список папок
  items <db>                список элементов
  inspect-key <db> <uuid>   разбор key_data элемента
  verify <db> <key-hex>     проверить HMAC всех элементов заданным ключом

ПРИМЕРЫ
  opclient info OnePassword.sqlite
  opclient items OnePassword.sqlite | head
  opclient verify OnePassword.sqlite 0011223344...

Расшифровка не реализована: соль для PBKDF2 находится внутри
зашифрованного блока encryptedSymmetricKey. См. `kdf_status`.
";

/// Безопасная альтернатива `outln`.
///
/// `opclient items | head` закрывает пайп на середине вывода, и обычный
/// `outln` на этом паникует. Здесь ошибка записи просто игнорируется —
/// так поступают git и ripgrep. Без `unsafe`, без зависимости от libc.
macro_rules! outln {
    () => {{
        use std::io::Write;
        let so = std::io::stdout();
        let mut l = so.lock();
        let _ = writeln!(l);
    }};
    ($($arg:tt)*) => {{
        use std::io::Write;
        let so = std::io::stdout();
        let mut l = so.lock();
        let _ = writeln!(l, $($arg)*);
    }};
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args[1] == "-h" || args[1] == "--help" || args[1] == "help" {
        print!("{USAGE}");
        return ExitCode::from(if args.len() < 3 { 2 } else { 0 });
    }

    let cmd = args[1].as_str();
    let db = Path::new(&args[2]);

    let r = match cmd {
        "info" => cmd_info(db),
        "folders" => cmd_folders(db),
        "items" => cmd_items(db),
        "inspect-key" => match args.get(3) {
            Some(u) => cmd_inspect_key(db, u),
            None => Err(Error::NotFound("нужен uuid элемента".into())),
        },
        "verify" => match args.get(3) {
            Some(k) => cmd_verify(db, k),
            None => Err(Error::NotFound("нужен ключ в hex".into())),
        },
        other => {
            eprintln!("неизвестная команда: {other}\n");
            print!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ошибка: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_info(db: &Path) -> opclient_core::Result<()> {
    let v = Vault::open(db)?;
    let s = v.summary()?;
    outln!("{}", serde_json::to_string_pretty(&s)?);

    outln!("\n--- master_key_data ---");
    match v.inspect_master_key_data() {
        Ok(r) => {
            outln!("размер поля   : {} B", r.total_len);
            outln!("тег заголовка : {}", hex8(&r.header_tag));
            match r.envelope {
                Some(e) => {
                    outln!("IV            : {}", hex(&e.iv));
                    outln!("шифротекст    : {} B", e.ciphertext_len);
                    outln!("HMAC (записан): {}", hex(&e.mac));
                }
                None => outln!("вложенный блоб: слишком мал для IV‖CT‖HMAC"),
            }
        }
        Err(e) => outln!("не разобран: {e}"),
    }

    outln!("\n--- статус расшифровки ---");
    outln!("{}", kdf::STATUS.reason());
    match Unavailable.master_key() {
        Ok(_) => outln!("ключ доступен"),
        Err(e) => outln!("ключ: {e}"),
    }
    Ok(())
}

fn cmd_folders(db: &Path) -> opclient_core::Result<()> {
    let v = Vault::open(db)?;
    let fs = v.folders()?;
    outln!("{} папок", fs.len());
    for f in fs {
        let tag = opdata_tag(&f.overview_data);
        outln!("  {}  {} B  тег={}", f.uuid, f.overview_data.len(), tag);
    }
    Ok(())
}

fn cmd_items(db: &Path) -> opclient_core::Result<()> {
    let v = Vault::open(db)?;
    let items = v.items()?;
    outln!("{} элементов", items.len());
    for i in &items {
        outln!(
            "  {}  cat={}  folder={}  key_data={} B  trashed={}  upd={}",
            i.uuid,
            i.category_uuid.as_deref().unwrap_or("-"),
            i.folder_uuid.as_deref().unwrap_or("-"),
            i.key_data.len(),
            i.trashed,
            i.updated_at
        );
    }
    Ok(())
}

fn cmd_inspect_key(db: &Path, uuid: &str) -> opclient_core::Result<()> {
    let v = Vault::open(db)?;
    let r = v.inspect_item_key(uuid)?;
    outln!("элемент  : {}", r.uuid);
    outln!("размер   : {} B", r.report.total_len);
    outln!("IV       : {}", hex(&r.report.iv));
    outln!("шифротекст: {} B", r.report.ciphertext_len);
    outln!("HMAC     : {}", hex(&r.report.mac));
    outln!("проверка : {:?}", r.report.hmac);
    Ok(())
}

fn cmd_verify(db: &Path, key_hex: &str) -> opclient_core::Result<()> {
    let key = parse_key(key_hex)?;
    let v = Vault::open(db)?;
    let scan = v.count_valid_mac(&key)?;
    outln!(
        "элементов: {}\nразобрано: {}\nHMAC верных: {}\nHMAC неверных: {}",
        scan.total,
        scan.parsed,
        scan.valid,
        scan.total.saturating_sub(scanned_valid(&scan))
    );
    if scan.valid == scan.parsed && scan.valid > 0 {
        outln!("\nКЛЮЧ ВЕРЕН — можно переходить к расшифровке.");
    } else if scan.valid == 0 {
        outln!("\nНи один HMAC не сошёлся: ключ неверен.");
    } else {
        outln!("\nЧастичное совпадение — ключ или охват неверны.");
    }
    Ok(())
}

fn scanned_valid(s: &opclient_core::vault::MacScan) -> usize {
    s.valid
}

fn parse_key(s: &str) -> opclient_core::Result<[u8; KEY_LEN]> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != KEY_LEN * 2 {
        return Err(Error::Crypto(format!(
            "ключ должен быть {}-байтным hex ({})",
            KEY_LEN,
            KEY_LEN * 2
        )));
    }
    let mut k = [0u8; KEY_LEN];
    for (i, byte) in k.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::Crypto("ключ не является hex".into()))?;
    }
    Ok(k)
}

fn opdata_tag(b: &[u8]) -> String {
    if b.len() >= 16 && &b[..8] == b"opdata01" {
        hex8(b[8..16].try_into().unwrap())
    } else {
        "-".into()
    }
}

fn hex8(b: &[u8; 8]) -> String {
    hex(b)
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}
