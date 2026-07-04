use vest_core::types::ScanSession;

pub(crate) struct ReportTarget {
    pub id: String,
    pub name: String,
    pub target_type: String,
    pub platform: Option<String>,
    pub metadata: serde_json::Value,
}

pub(crate) fn report_target(scan: &ScanSession) -> ReportTarget {
    let target = scan.metadata.get("target");
    let metadata = target
        .and_then(|t| t.get("metadata"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    ReportTarget {
        id: target
            .and_then(|t| string_field(t, "id"))
            .unwrap_or_else(|| scan.target_id.clone()),
        name: target
            .and_then(|t| string_field(t, "name"))
            .unwrap_or_else(|| scan.target_id.clone()),
        target_type: target
            .and_then(|t| string_field(t, "type"))
            .unwrap_or_else(|| "unknown".to_string()),
        platform: target
            .and_then(|t| string_field(t, "platform"))
            .or_else(|| {
                metadata
                    .get("platform")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            }),
        metadata,
    }
}

pub(crate) fn target_display(scan: &ScanSession) -> String {
    let target = report_target(scan);
    if target.target_type == "unknown" {
        target.name
    } else {
        format!("{} ({})", target.name, target.target_type)
    }
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
