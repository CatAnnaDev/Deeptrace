/// Protocol inference heuristics (very small placeholders)

pub fn entropy_estimate(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    // very crude: uniformness score via distinct byte ratio
    let mut seen = [false; 256];
    let mut uniq = 0usize;
    for &b in data {
        let idx = b as usize;
        if !seen[idx] {
            seen[idx] = true;
            uniq += 1;
        }
    }
    uniq as f64 / 256.0
}
