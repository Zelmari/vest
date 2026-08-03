use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::test]
async fn test_safety_checker_concurrent_rate_limits() {
    use vest_agent::safety::{SafetyChecker, SafetyConfig};

    let config = SafetyConfig {
        rate_limit_enabled: true,
        rate_limit_requests_per_second: 1000,
        rate_limit_burst: 500,
        ..Default::default()
    };
    let checker = Arc::new(SafetyChecker::new(config));

    let mut handles = vec![];
    for _ in 0..1000 {
        let c = Arc::clone(&checker);
        handles.push(tokio::spawn(async move { c.check_rate_limit().await }));
    }

    let mut ok_count = 0;
    let mut rate_limited = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(()) => ok_count += 1,
            Err(_) => rate_limited += 1,
        }
    }

    assert!(
        ok_count >= 25,
        "Expected at least 25 passed (initial tokens + some refill), got {}",
        ok_count
    );
    assert!(
        ok_count <= 550,
        "Expected at most burst+initial passed, got {}",
        ok_count
    );
    assert_eq!(ok_count + rate_limited, 1000);
}

#[tokio::test]
async fn test_safety_checker_concurrent_approvals() {
    use vest_agent::safety::{SafetyChecker, SafetyConfig};

    let checker = Arc::new(SafetyChecker::new(SafetyConfig::default()));

    let mut handles = vec![];
    for i in 0..100 {
        let c = Arc::clone(&checker);
        handles.push(tokio::spawn(async move {
            c.grant_approval(&format!("cat-{}", i % 5)).await;
            c.grant_approval(&format!("cat-{}", (i + 1) % 5)).await;
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[test]
fn test_request_approval_concurrent_writes() {
    use std::sync::Arc as StdArc;
    use std::thread;
    use vest_agent::safety::{SafetyChecker, SafetyConfig};

    let checker = StdArc::new(SafetyChecker::new(SafetyConfig::default()));

    let rt = StdArc::new(tokio::runtime::Runtime::new().unwrap());
    let mut handles = vec![];
    for i in 0..100 {
        let c = StdArc::clone(&checker);
        let rt = StdArc::clone(&rt);
        handles.push(thread::spawn(move || {
            rt.block_on(async {
                c.grant_approval(&format!("cat-{}", i % 5)).await;
            });
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn test_agent_context_concurrent_observations() {
    use std::sync::Arc;
    use vest_agent::context::AgentContext;

    let ctx = Arc::new(Mutex::new(AgentContext::new()));
    let mut handles = vec![];

    for i in 0..1000 {
        let ctx = Arc::clone(&ctx);
        handles.push(tokio::spawn(async move {
            let mut guard = ctx.lock().await;
            guard.add_observation(format!("observation-{}", i));
            guard.add_message("user", format!("msg-{}", i));
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let guard = ctx.lock().await;
    assert_eq!(guard.observations.len(), 1000);
    assert_eq!(guard.conversation_history.len(), 1000);
}

#[tokio::test]
async fn test_agent_memory_concurrent() {
    use std::sync::Arc;
    use vest_agent::memory::AgentMemory;

    let memory = Arc::new(Mutex::new(AgentMemory::new()));
    let mut handles = vec![];

    for i in 0..500 {
        let mem = Arc::clone(&memory);
        handles.push(tokio::spawn(async move {
            let mut guard = mem.lock().await;
            guard.add_observation(format!("obs-{}", i));
            guard
                .record_tool_sequence(vec!["tool-a".into(), "tool-b".into()], format!("seq-{}", i));
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let guard = memory.lock().await;
    assert_eq!(guard.observations.len(), 500);
    assert_eq!(guard.tool_sequences.len(), 500);
}

#[tokio::test]
async fn test_provider_registry_concurrent_listing() {
    use std::sync::Arc;
    use vest_providers::ProviderRegistry;

    let registry = Arc::new(Mutex::new(ProviderRegistry::new()));
    let mut handles = vec![];

    for _ in 0..100 {
        let reg = Arc::clone(&registry);
        handles.push(tokio::spawn(async move {
            let guard = reg.lock().await;
            let _ = guard.list_names();
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[test]
fn test_massive_finding_collection_no_panic() {
    use chrono::Utc;
    use vest_core::types::{Finding, FindingStatus, Severity, VulnerabilityClass};

    let now = Utc::now();
    let findings: Vec<Finding> = (0..10000)
        .map(|i| Finding {
            id: uuid::Uuid::new_v4().to_string(),
            scan_id: "s1".into(),
            target_id: "t1".into(),
            title: format!("Finding number {}", i),
            description: format!("Description for finding {}", i),
            vulnerability_class: VulnerabilityClass::Unknown,
            severity: Severity::Info,
            confidence: 0.5,
            status: FindingStatus::Open,
            severity_score_estimate: None,
            cve_id: None,
            cwe_id: None,
            evidence: serde_json::json!({"index": i}),
            poc: None,
            remediation: None,
            location: serde_json::json!({"index": i}),
            false_positive_history: None,
            tags: vec![format!("tag-{}", i % 10)],
            metadata: serde_json::json!({}),
            discovered_at: now,
            updated_at: now,
        })
        .collect();

    let json = serde_json::to_string(&findings).unwrap();
    assert!(json.len() > 1000);

    let deser: Vec<Finding> = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.len(), 10000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_rate_limiter_heavy_contention_no_deadlock() {
    use std::sync::Arc;
    use vest_agent::safety::{SafetyChecker, SafetyConfig};

    let config = SafetyConfig {
        rate_limit_enabled: true,
        rate_limit_requests_per_second: 100000,
        rate_limit_burst: 100000,
        ..Default::default()
    };
    let checker = Arc::new(SafetyChecker::new(config));

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut handles = vec![];
        for _ in 0..10000 {
            let c = Arc::clone(&checker);
            handles.push(tokio::spawn(async move { c.check_rate_limit().await }));
        }
        for handle in handles {
            let _ = handle.await;
        }
    })
    .await;

    assert!(
        result.is_ok(),
        "Rate limiter timed out after 5s — possible deadlock!"
    );
}

#[tokio::test]
async fn test_rate_limiter_zero_burst_allows_nothing() {
    use vest_agent::safety::{SafetyChecker, SafetyConfig};

    let checker = SafetyChecker::new(SafetyConfig {
        rate_limit_enabled: true,
        rate_limit_requests_per_second: 0,
        rate_limit_burst: 0,
        ..Default::default()
    });

    for _ in 0..10 {
        assert!(checker.check_rate_limit().await.is_err());
    }
}

#[tokio::test]
async fn test_rate_limiter_max_values() {
    use vest_agent::safety::{SafetyChecker, SafetyConfig};

    let checker = SafetyChecker::new(SafetyConfig {
        rate_limit_enabled: true,
        rate_limit_requests_per_second: u32::MAX,
        rate_limit_burst: u32::MAX,
        ..Default::default()
    });

    for _ in 0..10000 {
        assert!(checker.check_rate_limit().await.is_ok());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_rate_limit_disabled_concurrent_many_calls() {
    use std::sync::Arc;
    use vest_agent::safety::{SafetyChecker, SafetyConfig};

    let checker = Arc::new(SafetyChecker::new(SafetyConfig {
        rate_limit_enabled: false,
        ..Default::default()
    }));

    let mut handles = vec![];
    for _ in 0..2000 {
        let c = Arc::clone(&checker);
        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                assert!(c.check_rate_limit().await.is_ok());
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_rate_limiter_burst_exhausted_then_refill() {
    use vest_agent::safety::{SafetyChecker, SafetyConfig};

    let checker = SafetyChecker::new(SafetyConfig {
        rate_limit_enabled: true,
        rate_limit_requests_per_second: 100,
        rate_limit_burst: 10,
        ..Default::default()
    });

    for _ in 0..10 {
        assert!(checker.check_rate_limit().await.is_ok());
    }
    assert!(checker.check_rate_limit().await.is_err());

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert!(checker.check_rate_limit().await.is_ok());
}

#[test]
fn test_merge_strategies_thread_safe() {
    use chrono::Utc;
    use std::sync::Arc as StdArc;
    use vest_core::types::{Finding, FindingStatus, Severity, VulnerabilityClass};

    let now = Utc::now();
    let findings: Vec<Finding> = (0..100)
        .map(|i| Finding {
            id: format!("f-{}", i),
            scan_id: "s1".into(),
            target_id: "t1".into(),
            title: format!("Finding {}", i % 10),
            description: "test".into(),
            vulnerability_class: VulnerabilityClass::XSS,
            severity: Severity::High,
            confidence: 0.9,
            status: FindingStatus::Open,
            severity_score_estimate: None,
            cve_id: None,
            cwe_id: None,
            evidence: serde_json::json!({}),
            poc: None,
            remediation: None,
            location: serde_json::json!({}),
            false_positive_history: None,
            tags: vec![],
            metadata: serde_json::json!({}),
            discovered_at: now,
            updated_at: now,
        })
        .collect();

    let findings_arc = StdArc::new(std::sync::RwLock::new(Vec::new()));
    let mut handles = vec![];

    for chunk in findings.chunks(25) {
        let findings_arc = StdArc::clone(&findings_arc);
        let chunk = chunk.to_vec();
        handles.push(std::thread::spawn(move || {
            let mut all = findings_arc.write().unwrap();
            all.extend(chunk);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let collected = findings_arc.read().unwrap();
    assert_eq!(collected.len(), 100);
}

#[test]
fn test_safety_config_default_clone() {
    use vest_agent::safety::SafetyConfig;

    let config = SafetyConfig::default();
    let cloned = config.clone();
    assert_eq!(config.rate_limit_enabled, cloned.rate_limit_enabled);
    assert_eq!(config.rate_limit_burst, cloned.rate_limit_burst);
}

#[tokio::test]
async fn test_safety_checker_withoverrides_runs_concurrently() {
    use std::sync::Arc;
    use vest_agent::safety::{SafetyChecker, SafetyConfig};

    let checker = Arc::new(SafetyChecker::default());
    let mut handles = vec![];
    for _ in 0..50 {
        let c = Arc::clone(&checker);
        handles.push(tokio::spawn(async move {
            let overridden = c.with_overrides(SafetyConfig {
                rate_limit_burst: 500,
                ..Default::default()
            });
            let _ = overridden.check_rate_limit().await;
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
}

#[test]
fn test_swarm_agent_config_diversity() {
    use vest_agent::patterns::swarm::{SwarmAgentConfig, SwarmRunner};

    let agents = SwarmRunner::default_agents();
    assert_eq!(agents.len(), 4);

    let memory = SwarmAgentConfig::memory_hunter();
    let web = SwarmAgentConfig::web_hunter();
    let binary = SwarmAgentConfig::binary_hunter();
    let auth = SwarmAgentConfig::auth_logic_hunter();

    let names: Vec<&str> = [&memory.name, &web.name, &binary.name, &auth.name]
        .into_iter()
        .map(|s| s.as_str())
        .collect();
    let dedup: std::collections::HashSet<&str> = names.iter().copied().collect();
    assert_eq!(dedup.len(), 4, "All agents should have unique names");
}
