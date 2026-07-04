use crate::TargetsArgs;
use vest_core::types::{Target, TargetType};
use vest_storage::{schema, targets, ConnectionPool};

pub async fn run(args: TargetsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let db_path = get_db_path();
    let dir = std::path::Path::new(&db_path)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(dir)?;
    let pool = ConnectionPool::new(&db_path)?;
    schema::run_migrations(pool.conn()).ok();

    match args {
        TargetsArgs::List => {
            let conn = pool.conn();
            let list = targets::list_targets(conn).unwrap_or_default();

            if list.is_empty() {
                println!("No targets found. Add one with: vest targets add <name>");
                return Ok(());
            }

            println!("{:<36} | {:<20} | {:<12} | Details", "ID", "Name", "Type");
            println!("{}", "-".repeat(100));
            for t in &list {
                let id = &t.id[..t.id.len().min(34)];
                let name = &t.name[..t.name.len().min(18)];
                let details = match t.target_type {
                    TargetType::Web => t.url_str.as_deref().unwrap_or("no url"),
                    TargetType::Binary => t.path.as_deref().unwrap_or("no path"),
                    TargetType::Process => &format!(
                        "PID: {}",
                        t.pid.map(|p| p.to_string()).unwrap_or("?".into())
                    ),
                    TargetType::Network => t.host.as_deref().unwrap_or("no host"),
                    _ => "-",
                };
                println!(
                    "{:<36} | {:<20} | {:<12} | {}",
                    id, name, t.target_type, details
                );
            }
            println!("Total: {}", list.len());
        }
        TargetsArgs::Show { id } => match targets::get_target(pool.conn(), &id) {
            Ok(t) => {
                println!("Target: {}", t.name);
                println!("  ID:   {}", t.id);
                println!("  Type: {}", t.target_type);
                if let Some(p) = &t.path {
                    println!("  Path: {}", p);
                }
                if let Some(u) = &t.url_str {
                    println!("  URL:  {}", u);
                }
                if let Some(pid) = t.pid {
                    println!("  PID:  {}", pid);
                }
                if let Some(h) = &t.host {
                    println!("  Host: {}", h);
                }
                println!("  Created: {}", t.created_at);
            }
            Err(_) => println!("Target '{}' not found", id),
        },
        TargetsArgs::Add { target: name } => {
            let now = chrono::Utc::now();
            let t = Target {
                id: vest_core::ids::new_id(),
                name: name.clone(),
                target_type: detect_target_type(&name),
                path: if std::path::Path::new(&name).exists() {
                    Some(name.clone())
                } else {
                    None
                },
                url_str: if name.contains("://") {
                    Some(name.clone())
                } else if !name.contains('/') && !name.contains(' ') && name.contains('.') {
                    Some(format!("https://{}", name))
                } else {
                    None
                },
                pid: name.parse::<u32>().ok(),
                host: if name.contains(':') && !name.contains("://") {
                    Some(name.clone())
                } else {
                    None
                },
                metadata: serde_json::json!({}),
                created_at: now,
                updated_at: now,
            };
            targets::insert_target(pool.conn(), &t)?;
            println!(
                "Added target: {} (type: {}, id: {})",
                name,
                t.target_type,
                &t.id[..8]
            );
        }
        TargetsArgs::Remove { id } => match targets::delete_target(pool.conn(), &id) {
            Ok(()) => println!("Removed target {}", id),
            Err(e) => println!("Failed to remove target: {}", e),
        },
    }
    Ok(())
}

fn detect_target_type(name: &str) -> TargetType {
    if name.contains("://")
        || (name.contains('.')
            && !name.contains('/')
            && !name.contains('\\')
            && !name.contains(':'))
    {
        TargetType::Web
    } else if name.ends_with(".exe")
        || name.ends_with(".dll")
        || name.ends_with(".so")
        || name.ends_with(".elf")
    {
        TargetType::Binary
    } else if name.parse::<u32>().is_ok() {
        TargetType::Process
    } else if name.contains(':') {
        TargetType::Network
    } else {
        TargetType::File
    }
}

fn get_db_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = format!("{}/.vest", home);
    std::fs::create_dir_all(&dir).ok();
    format!("{}/vest.db", dir)
}
