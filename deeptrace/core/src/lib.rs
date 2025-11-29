#![allow(dead_code)]

pub mod capture;
pub mod reassembly;

pub fn version() -> &'static str { "core 0.1.0" }


pub fn hex_dump(data: &[u8]) -> String {
    let mut out = String::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("{:04x}:  ", i * 16));

        for b in chunk {
            out.push_str(&format!("{:02x} ", b));
        }

        // align
        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) {
                out.push_str("   ");
            }
        }

        out.push_str(" |");

        for b in chunk {
            let c = if b.is_ascii_graphic() { *b as char } else { '.' };
            out.push(c);
        }

        out.push_str("|\n");
    }

    out
}
