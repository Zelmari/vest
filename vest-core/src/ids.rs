use uuid::Uuid;

/// Generate a new unique UUID v4 identifier as a string.
pub fn new_id() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_id_is_not_empty() {
        let id = new_id();
        assert!(!id.is_empty());
        assert_eq!(id.len(), 36);
    }

    #[test]
    fn test_new_id_is_unique() {
        let id1 = new_id();
        let id2 = new_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_new_id_is_valid_uuid() {
        let id = new_id();
        Uuid::parse_str(&id).expect("Should be a valid UUID");
    }

    #[test]
    fn test_many_ids_are_unique() {
        let ids: Vec<String> = (0..100).map(|_| new_id()).collect();
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 100);
    }
}
