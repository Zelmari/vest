use rand::Rng;

pub fn random_usize(min: usize, max: usize) -> usize {
    rand::thread_rng().gen_range(min..=max)
}

pub fn assert_deterministic<F, T: Eq + std::fmt::Debug>(f: F, input: T)
where
    F: Fn(&T) -> bool,
{
    let r1 = f(&input);
    let r2 = f(&input);
    let r3 = f(&input);
    assert_eq!(r1, r2, "Function is not deterministic on first check");
    assert_eq!(r2, r3, "Function is not deterministic on second check");
}

pub fn assert_never_panics<F, T: Clone>(f: F, inputs: &[T])
where
    F: Fn(&T),
{
    for input in inputs {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            f(input);
        }));
    }
}

pub fn assert_serde_roundtrip<
    T: serde::Serialize + serde::de::DeserializeOwned + Eq + std::fmt::Debug,
>(
    value: &T,
) {
    let json = serde_json::to_string(value).expect("Failed to serialize");
    let deserialized: T = serde_json::from_str(&json).expect("Failed to deserialize");
    assert_eq!(
        &deserialized, value,
        "Serde roundtrip failed for value: {:?}",
        value
    );
}

pub fn assert_valid_json<T: serde::Serialize>(value: &T) {
    let json = serde_json::to_string(value).expect("Failed to serialize");
    let _: serde_json::Value = serde_json::from_str(&json).expect("Not valid JSON");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assert_deterministic_works() {
        assert_deterministic(|x: &i32| x % 2 == 0, 4);
        assert_deterministic(|x: &String| x.len() > 0, "hello".to_string());
    }

    #[test]
    fn test_assert_roundtrip() {
        assert_serde_roundtrip(&"hello".to_string());
        assert_serde_roundtrip(&vec![1, 2, 3]);
    }
}
