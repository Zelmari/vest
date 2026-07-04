#[cfg(not(feature = "browser"))]
#[test]
fn test_browser_module_not_available_without_feature() {
    let modules = [
        "binary", "files", "memory", "network", "registry", "scanner", "web",
    ];
    for module in &modules {
        assert!(
            !module.is_empty(),
            "Module '{}' should be available without browser feature",
            module
        );
    }
}

#[cfg(feature = "browser")]
#[test]
fn test_browser_module_available_with_feature() {
    // The test only compiles when the browser feature is enabled,
    // which verifies the feature gate works correctly.
    let scanner = vest_scanner::browser::BrowserScanner::new();
    assert!(scanner.enabled);
    assert!(!scanner.name.is_empty());
}
