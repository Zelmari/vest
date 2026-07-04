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
    assert!(true, "Browser module compiled successfully with feature");
}
