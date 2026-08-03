use crate::ConfigArgs;
use std::path::{Path, PathBuf};
use toml_edit::DocumentMut;
use vest_core::error::VestError;

pub async fn run(
    args: ConfigArgs,
    config_path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = resolve_config_path(config_path.as_ref());
    match args {
        ConfigArgs::Init => {
            let path = PathBuf::from("vest.toml");
            if path.exists() {
                println!("vest.toml already exists. Use --force to overwrite.");
                return Ok(());
            }
            let default_config = vest_config::default_config();
            let toml_str = toml::to_string_pretty(&default_config)?;
            std::fs::write(&path, toml_str)?;
            println!("Created vest.toml with default configuration");
        }
        ConfigArgs::Show => match vest_config::load_config(&config_path) {
            Ok(config) => {
                let toml_str = toml::to_string_pretty(&config)?;
                println!("Config loaded from: {}", config_path.display());
                println!("{}", toml_str);
            }
            Err(e) if !config_path.exists() => {
                println!("Could not load config: {}", e);
                println!("Showing defaults:");
                let default = vest_config::default_config();
                let toml_str = toml::to_string_pretty(&default)?;
                println!("{}", toml_str);
            }
            Err(e) => {
                return Err(format!(
                    "Failed to load config {}: {e}. Refusing silent defaults for a present file.",
                    config_path.display()
                )
                .into());
            }
        },
        ConfigArgs::Validate => {
            let config = vest_config::load_config(&config_path)
                .map_err(|e| format!("Configuration error at {}: {e}", config_path.display()))?;
            println!("Configuration is valid");
            println!(
                "  Provider: {}",
                config
                    .providers
                    .as_ref()
                    .map(|p| &p.default.provider[..])
                    .unwrap_or("not configured")
            );
            println!("  Agent pattern: {}", config.agent.default_pattern);
            println!(
                "  Scanners enabled: memory={}, binary={}, web={}, browser={}, network={}, files={}",
                config.scanner.memory.enabled,
                config.scanner.binary.enabled,
                config.scanner.web.enabled,
                config.scanner.browser.enabled,
                config.scanner.network.enabled,
                config.scanner.files.enabled,
            );
        }
        ConfigArgs::Path => {
            if config_path.exists() {
                println!("{}", config_path.display());
            } else {
                println!(
                    "No config file found at {}. Run 'vest config init' to create one.",
                    config_path.display()
                );
            }
        }
        ConfigArgs::Set { key, value } => {
            if !config_path.exists() {
                return Err(VestError::Config(format!(
                    "No config file found at {}. Run 'vest config init' to create one.",
                    config_path.display()
                ))
                .into());
            }

            let content = std::fs::read_to_string(&config_path)?;
            let mut doc = content.parse::<DocumentMut>()?;

            let valid_keys = gather_dotted_keys(&doc);
            if !valid_keys.contains(&key) && !key_starts_with_known_path(&doc, &key) {
                let suggestions = closest_matches(&key, &valid_keys, 3);
                let mut msg = format!("Unknown config key: '{key}'");
                if !suggestions.is_empty() {
                    msg.push_str("\nDid you mean?");
                    for s in suggestions {
                        msg.push_str(&format!("\n  {s}"));
                    }
                }
                return Err(VestError::InvalidInput(msg).into());
            }

            let parsed_value = parse_value(&value);
            set_dotted_key(&mut doc, &key, parsed_value)?;

            std::fs::write(&config_path, doc.to_string())?;
            println!("Set {} = {}", key, value);
        }
    }
    Ok(())
}

fn parse_value(s: &str) -> toml_edit::Value {
    let lower = s.trim().to_lowercase();
    match lower.as_str() {
        "true" => return toml_edit::Value::from(true),
        "false" => return toml_edit::Value::from(false),
        _ => {}
    }
    if let Ok(i) = s.parse::<i64>() {
        return toml_edit::Value::from(i);
    }
    toml_edit::Value::from(s)
}

fn set_dotted_key(
    doc: &mut DocumentMut,
    key: &str,
    value: toml_edit::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = key.split('.').collect();
    if parts.len() == 1 {
        doc[parts[0]] = toml_edit::Item::Value(value);
        return Ok(());
    }
    let mut current = doc.as_table_mut();
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            current[part] = toml_edit::Item::Value(value.clone());
        } else {
            let entry = current.entry(part);
            current = match entry {
                toml_edit::Entry::Occupied(o) => o.into_mut(),
                toml_edit::Entry::Vacant(v) => {
                    let mut t = toml_edit::Table::new();
                    t.set_implicit(true);
                    v.insert(toml_edit::Item::Table(t))
                }
            }
            .as_table_mut()
            .ok_or_else(|| format!("'{}' is not a table", parts[0..=i].join(".")))?;
        }
    }
    Ok(())
}

fn gather_dotted_keys(doc: &DocumentMut) -> Vec<String> {
    let mut keys = Vec::new();
    let mut current_path = Vec::new();
    collect_keys(doc.as_table(), &mut current_path, &mut keys);
    keys
}

fn collect_keys(table: &toml_edit::Table, path: &mut Vec<String>, keys: &mut Vec<String>) {
    for (key, item) in table.iter() {
        path.push(key.to_string());
        match item {
            toml_edit::Item::Table(t) => {
                collect_keys(t, path, keys);
            }
            toml_edit::Item::Value(_) => {
                keys.push(path.join("."));
            }
            _ => {}
        }
        path.pop();
    }
}

fn key_starts_with_known_path(doc: &DocumentMut, dotted_key: &str) -> bool {
    let parts: Vec<&str> = dotted_key.split('.').collect();
    if parts.is_empty() {
        return false;
    }
    let mut current = doc.as_table();
    for part in &parts[..parts.len() - 1] {
        match current.get(part) {
            Some(toml_edit::Item::Table(t)) => current = t,
            _ => return false,
        }
    }
    true
}

fn closest_matches(target: &str, candidates: &[String], limit: usize) -> Vec<String> {
    let mut scored: Vec<(usize, &String)> = candidates
        .iter()
        .filter_map(|c| {
            let d = edit_distance(target, c);
            if d <= std::cmp::max(target.len(), c.len()) / 2 {
                Some((d, c))
            } else {
                None
            }
        })
        .collect();
    scored.sort_by_key(|(d, _)| *d);
    scored.truncate(limit);
    scored.into_iter().map(|(_, s)| s.clone()).collect()
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let n = a.len();
    let m = b.len();
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in dp.iter_mut().enumerate().take(n + 1) {
        row[0] = i;
    }
    for (j, cell) in dp[0].iter_mut().enumerate().take(m + 1) {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }
    dp[n][m]
}

/// Honour the global `-c/--config` path when present; otherwise fall back to
/// `./vest.toml` or `~/.vest/vest.toml`.
pub(crate) fn resolve_config_path(cli_path: &Path) -> PathBuf {
    if cli_path.as_os_str() != "vest.toml" || cli_path.exists() {
        return cli_path.to_path_buf();
    }
    let local = PathBuf::from("vest.toml");
    if local.exists() {
        return local;
    }
    let home = dirs_home().unwrap_or_else(|| PathBuf::from("."));
    home.join(".vest").join("vest.toml")
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("USERPROFILE").ok().map(PathBuf::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_simple_key() {
        let tmp = std::env::temp_dir().join("vest_test_set_simple.toml");
        let content = r#"
[general]
workspace_dir = "~/.vest"

[agent]
default_pattern = "pipeline"
max_concurrent_agents = 8

[scanner.memory]
enabled = true

[scanner.web]
enabled = true
"#;
        std::fs::write(&tmp, content).unwrap();

        let content = std::fs::read_to_string(&tmp).unwrap();
        let mut doc = content.parse::<DocumentMut>().unwrap();
        let new_value = toml_edit::Value::from("swarm");
        set_dotted_key(&mut doc, "agent.default_pattern", new_value).unwrap();
        std::fs::write(&tmp, doc.to_string()).unwrap();

        let updated = std::fs::read_to_string(&tmp).unwrap();
        let doc: DocumentMut = updated.parse().unwrap();
        let val = doc["agent"]["default_pattern"].as_str().unwrap();
        assert_eq!(val, "swarm");

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_set_nested_key() {
        let tmp = std::env::temp_dir().join("vest_test_set_nested.toml");
        let content = r#"
[general]
workspace_dir = "~/.vest"

[agent]
default_pattern = "pipeline"

[scanner.memory]
enabled = true

[scanner.web]
enabled = true
"#;
        std::fs::write(&tmp, content).unwrap();

        let content = std::fs::read_to_string(&tmp).unwrap();
        let mut doc = content.parse::<DocumentMut>().unwrap();
        let new_value = toml_edit::Value::from(false);
        set_dotted_key(&mut doc, "scanner.memory.enabled", new_value).unwrap();
        std::fs::write(&tmp, doc.to_string()).unwrap();

        let updated = std::fs::read_to_string(&tmp).unwrap();
        let doc: DocumentMut = updated.parse().unwrap();
        let val = doc["scanner"]["memory"]["enabled"].as_bool().unwrap();
        assert!(!val);

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_set_bool_true() {
        let tmp = std::env::temp_dir().join("vest_test_set_bool.toml");
        let content = r#"
[general]
workspace_dir = "~/.vest"

[scanner.memory]
enabled = true
"#;
        std::fs::write(&tmp, content).unwrap();

        let content = std::fs::read_to_string(&tmp).unwrap();
        let mut doc = content.parse::<DocumentMut>().unwrap();
        let new_value = parse_value("false");
        set_dotted_key(&mut doc, "scanner.memory.enabled", new_value).unwrap();
        std::fs::write(&tmp, doc.to_string()).unwrap();

        let updated = std::fs::read_to_string(&tmp).unwrap();
        let doc: DocumentMut = updated.parse().unwrap();
        assert!(!doc["scanner"]["memory"]["enabled"].as_bool().unwrap());

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_set_integer() {
        let tmp = std::env::temp_dir().join("vest_test_set_int.toml");
        let content = r#"
[agent]
max_concurrent_agents = 8
"#;
        std::fs::write(&tmp, content).unwrap();

        let content = std::fs::read_to_string(&tmp).unwrap();
        let mut doc = content.parse::<DocumentMut>().unwrap();
        let new_value = parse_value("16");
        set_dotted_key(&mut doc, "agent.max_concurrent_agents", new_value).unwrap();
        std::fs::write(&tmp, doc.to_string()).unwrap();

        let updated = std::fs::read_to_string(&tmp).unwrap();
        let doc: DocumentMut = updated.parse().unwrap();
        let val = doc["agent"]["max_concurrent_agents"].as_integer().unwrap();
        assert_eq!(val, 16);

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_parse_value_bool() {
        let v = parse_value("true");
        assert!(v.as_bool().unwrap());
        let v = parse_value("false");
        assert!(!v.as_bool().unwrap());
    }

    #[test]
    fn test_parse_value_integer() {
        let v = parse_value("42");
        assert_eq!(v.as_integer().unwrap(), 42);
        let v = parse_value("-17");
        assert_eq!(v.as_integer().unwrap(), -17);
    }

    #[test]
    fn test_parse_value_string() {
        let v = parse_value("hello");
        assert_eq!(v.as_str().unwrap(), "hello");
    }

    #[test]
    fn test_gather_dotted_keys() {
        let content = r#"
[general]
workspace_dir = "~/.vest"

[agent]
default_pattern = "pipeline"

[scanner.memory]
enabled = true
"#;
        let doc = content.parse::<DocumentMut>().unwrap();
        let keys = gather_dotted_keys(&doc);
        assert!(keys.contains(&"general.workspace_dir".to_string()));
        assert!(keys.contains(&"agent.default_pattern".to_string()));
        assert!(keys.contains(&"scanner.memory.enabled".to_string()));
    }

    #[test]
    fn test_edit_distance() {
        assert_eq!(edit_distance("abc", "abc"), 0);
        assert_eq!(edit_distance("abc", "abd"), 1);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }

    #[test]
    fn test_closest_matches() {
        let candidates = vec![
            "agent.default_pattern".to_string(),
            "agent.max_concurrent_agents".to_string(),
            "scanner.memory.enabled".to_string(),
        ];
        let matches = closest_matches("agent.default_patern", &candidates, 3);
        assert!(!matches.is_empty());
        assert!(matches.contains(&"agent.default_pattern".to_string()));
    }

    #[test]
    fn test_key_starts_with_known_path() {
        let content = r#"
[agent]
default_pattern = "pipeline"
[scanner.memory]
enabled = true
"#;
        let doc = content.parse::<DocumentMut>().unwrap();
        assert!(key_starts_with_known_path(&doc, "agent.default_pattern"));
        assert!(key_starts_with_known_path(&doc, "agent.nonexistent_key"));
        assert!(!key_starts_with_known_path(&doc, "nonexistent.something"));
    }
}
