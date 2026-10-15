//! CLI for reading a 1Password backup.
//!
//! Subcommands:
//! - `info <db>` — summary and KDF status
//! - `folders <db>` — list of folders (uuid + blob geometry)
//! - `items <db>` — list of items (uuid, category, folder, time)
//! - `inspect-key <db> <uuid>` — parse one item's `key_data`
//! - `verify <db> <key-hex>` — bulk HMAC check with the given key
//!
//! A key is never read from command-line arguments in the clear,
//! even when given as hex — deliberately: arguments are visible in `ps`
//! and in shell history.

use std::path::Path;
use std::process::ExitCode;

use opclient_core::{kdf, keys::Unavailable, Error, KeyProvider, Vault, KEY_LEN};

const USAGE: &str = "\
opclient — reading a 1Password backup (.1p4), read-only

USAGE
  opclient <command> <path-to-OnePassword.sqlite> [arguments]

COMMANDS
  info <db>                 summary: profile, counters, DB SHA-256, KDF status
  folders <db>              list of folders
  items <db>                list of items
  inspect-key <db> <uuid>   parse an item's key_data
  verify <db> <key-hex>     check the HMAC of every item against the given key

EXAMPLES
  opclient info OnePassword.sqlite
  opclient items OnePassword.sqlite | head
  opclient verify OnePassword.sqlite 0011223344...

Decryption is not implemented: the PBKDF2 salt lives inside the
encrypted encryptedSymmetricKey block. See `kdf_status`.
";

/// A safe alternative to `outln`.
///
/// `opclient items | head` closes the pipe halfway through the output, and a
/// plain `outln` panics on that. Here a write error is simply ignored —
/// the way git and ripgrep do it. No `unsafe`, no libc dependency.
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
            None => Err(Error::NotFound("item uuid required".into())),
        },
        "verify" => match args.get(3) {
            Some(k) => cmd_verify(db, k),
            None => Err(Error::NotFound("a hex key required".into())),
        },
        other => {
            eprintln!("unknown command: {other}\n");
            print!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
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
            outln!("size          : {} B", r.total_len);
            outln!("header tag    : {}", hex8(&r.header_tag));
            match r.envelope {
                Some(e) => {
                    outln!("IV            : {}", hex(&e.iv));
                    outln!("ciphertext    : {} B", e.ciphertext_len);
                    outln!("HMAC (stored) : {}", hex(&e.mac));
                }
                None => outln!("nested blob: too small for IV‖CT‖HMAC"),
            }
        }
        Err(e) => outln!("not parsed: {e}"),
    }

    outln!("\n--- decryption status ---");
    outln!("{}", kdf::STATUS.reason());
    match Unavailable.master_key() {
        Ok(_) => outln!("key available"),
        Err(e) => outln!("key: {e}"),
    }
    Ok(())
}

fn cmd_folders(db: &Path) -> opclient_core::Result<()> {
    let v = Vault::open(db)?;
    let fs = v.folders()?;
    outln!("{} folders", fs.len());
    for f in fs {
        let tag = opdata_tag(&f.overview_data);
        outln!("  {}  {} B  tag={}", f.uuid, f.overview_data.len(), tag);
    }
    Ok(())
}

fn cmd_items(db: &Path) -> opclient_core::Result<()> {
    let v = Vault::open(db)?;
    let items = v.items()?;
    outln!("{} items", items.len());
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
    outln!("item      : {}", r.uuid);
    outln!("size      : {} B", r.report.total_len);
    outln!("IV        : {}", hex(&r.report.iv));
    outln!("ciphertext: {} B", r.report.ciphertext_len);
    outln!("HMAC      : {}", hex(&r.report.mac));
    outln!("check     : {:?}", r.report.hmac);
    Ok(())
}

fn cmd_verify(db: &Path, key_hex: &str) -> opclient_core::Result<()> {
    let key = parse_key(key_hex)?;
    let v = Vault::open(db)?;
    let scan = v.count_valid_mac(&key)?;
    outln!(
        "items: {}\nparsed: {}\nHMAC valid: {}\nHMAC invalid: {}",
        scan.total,
        scan.parsed,
        scan.valid,
        scan.total.saturating_sub(scanned_valid(&scan))
    );
    if scan.valid == scan.parsed && scan.valid > 0 {
        outln!("\nKEY IS CORRECT — decryption can proceed.");
    } else if scan.valid == 0 {
        outln!("\nNot a single HMAC matched: the key is wrong.");
    } else {
        outln!("\nPartial match — the key or the coverage is wrong.");
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
            "key must be a {}-byte hex value ({})",
            KEY_LEN,
            KEY_LEN * 2
        )));
    }
    let mut k = [0u8; KEY_LEN];
    for (i, byte) in k.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::Crypto("key is not hex".into()))?;
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
