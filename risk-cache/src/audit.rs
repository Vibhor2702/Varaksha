use serde_json::Value;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::Path;

/// Append one structured JSON event to a JSONL audit file.
/// Best-effort: returns an error string for caller-side warning logs.
pub fn append_jsonl(path: &str, event: Value) -> Result<(), String> {
    let target = Path::new(path);
    if let Some(parent) = target.parent() {
        create_dir_all(parent)
            .map_err(|e| format!("failed to create audit directory {}: {}", parent.display(), e))?;
    }

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(target)
        .map_err(|e| format!("failed to open audit file {}: {}", target.display(), e))?;

    let mut line = serde_json::to_string(&event)
        .map_err(|e| format!("failed to serialize audit event: {}", e))?;
    line.push('\n');

    f.write_all(line.as_bytes())
        .map_err(|e| format!("failed to write audit event: {}", e))
}
