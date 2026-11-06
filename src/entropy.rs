//! Shannon entropy in bits per byte.

pub fn shannon(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total = total as f64;
    let mut h = 0.0;
    for c in counts.iter() {
        if *c > 0 {
            let p = *c as f64 / total;
            h -= p * p.log2();
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_looking_is_high() {
        assert!(shannon("aB3xK9mQ2pL7vN4rT8wY1zC6") > 4.0);
    }

    #[test]
    fn english_word_is_low() {
        assert!(shannon("password") < 3.0);
    }

    #[test]
    fn repeated_is_zero() {
        assert_eq!(shannon("aaaaaaaa"), 0.0);
    }
}
