use std::collections::HashSet;
use vest_core::new_id;

#[test]
fn test_100000_ids_are_unique() {
    let ids: Vec<String> = (0..100000).map(|_| new_id()).collect();
    let set: HashSet<&String> = ids.iter().collect();
    assert_eq!(set.len(), ids.len(), "ID collision detected in 100000 IDs!");
}

#[test]
fn test_id_format_is_consistent() {
    let id = new_id();
    // UUIDv4 format: 8-4-4-4-12 hex digits with dashes
    let parts: Vec<&str> = id.split('-').collect();
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[0].len(), 8);
    assert_eq!(parts[1].len(), 4);
    assert_eq!(parts[2].len(), 4);
    assert_eq!(parts[3].len(), 4);
    assert_eq!(parts[4].len(), 12);
    // All hex characters
    assert!(id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
}

#[test]
fn test_id_thread_safety() {
    use std::thread;
    let mut handles = vec![];
    for _ in 0..100 {
        handles.push(thread::spawn(|| {
            let mut ids = Vec::new();
            for _ in 0..100 {
                ids.push(new_id());
            }
            ids
        }));
    }

    let mut all_ids = HashSet::new();
    for handle in handles {
        let ids = handle.join().unwrap();
        for id in ids {
            assert!(all_ids.insert(id), "Duplicate ID across threads!");
        }
    }

    assert_eq!(all_ids.len(), 10000);
}

#[test]
fn test_ids_generated_rapidly() {
    let mut set = HashSet::new();
    for _ in 0..50000 {
        let id = new_id();
        assert!(set.insert(id), "Collision during rapid generation!");
    }
}

#[test]
fn test_id_not_empty_and_not_hardcoded() {
    let id1 = new_id();
    let id2 = new_id();
    assert!(!id1.is_empty());
    assert!(!id2.is_empty());
    assert_ne!(id1, id2);
}

#[test]
fn test_id_always_36_chars() {
    for _ in 0..1000 {
        assert_eq!(new_id().len(), 36);
    }
}

#[test]
fn test_id_version_is_4() {
    // UUIDv4: 3rd group starts with '4'
    // Format: xxxxxxxx-xxxx-Vxxx-yxxx-xxxxxxxxxxxx where V=4, y={8,9,a,b}
    for _ in 0..100 {
        let id = new_id();
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts[2].chars().next().unwrap(), '4', "Not UUIDv4: {}", id);
        let variant_char = parts[3].chars().next().unwrap();
        assert!(
            variant_char == '8'
                || variant_char == '9'
                || variant_char == 'a'
                || variant_char == 'b',
            "Invalid UUID variant in: {}",
            id
        );
    }
}

#[test]
fn test_id_lowercase_only() {
    for _ in 0..1000 {
        let id = new_id();
        assert!(id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        assert!(
            !id.chars().any(|c| c.is_uppercase()),
            "UUID should be lowercase: {}",
            id
        );
    }
}

#[test]
fn test_id_distinct_in_tight_loop() {
    // Generate IDs in the tightest possible loop
    let mut prev = String::new();
    for _ in 0..1000 {
        let id = new_id();
        assert_ne!(id, prev);
        prev = id;
    }
}
