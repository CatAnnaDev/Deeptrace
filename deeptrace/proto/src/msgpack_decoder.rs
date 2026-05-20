use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Display;
// ============================================================================
// AUTO DETECTION AND PARSING
// ============================================================================

#[derive(Debug, Clone)]
pub enum ParsedData {
    Json(Value),
    MsgPack(Value),
    Cbor(Value),
    Bson(Value),
    Bencode(Value),
    Protobuf(Value),
    Form(Value),
    Yaml(Value),
    Toml(Value),
    Xml(String),
    Jwt {
        header: Value,
        payload: Value,
    },
    Text(String),
    Compressed {
        format: String,
        decompressed: Vec<u8>,
    },
    Binary {
        format: String,
        data: Vec<u8>,
    },
}

/// Auto-detect format and parse buffer to appropriate type
pub fn auto_parse(buf: &[u8]) -> Result<ParsedData> {
    // Empty buffer
    if buf.is_empty() {
        return Ok(ParsedData::Binary {
            format: "empty".to_string(),
            data: Vec::new(),
        });
    }

    // Try compression formats first (by magic bytes)
    if buf.len() >= 2 {
        // Gzip
        if buf[0..2] == [0x1f, 0x8b] {
            if let Ok(decompressed) = decompress_gzip(buf) {
                return Ok(ParsedData::Compressed {
                    format: "gzip".to_string(),
                    decompressed,
                });
            }
        }
        // Bzip2
        if buf[0..2] == [0x42, 0x5a] {
            if let Ok(decompressed) = decompress_bzip2(buf) {
                return Ok(ParsedData::Compressed {
                    format: "bzip2".to_string(),
                    decompressed,
                });
            }
        }
    }

    if buf.len() >= 4 {
        // Zstd
        if buf[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
            if let Ok(decompressed) = decompress_zstd(buf) {
                return Ok(ParsedData::Compressed {
                    format: "zstd".to_string(),
                    decompressed,
                });
            }
        }
    }

    // Try text-based formats if valid UTF-8
    if let Ok(text) = std::str::from_utf8(buf) {
        let trimmed = text.trim();

        // JSON
        if (trimmed.starts_with('{') && trimmed.ends_with('}'))
            || (trimmed.starts_with('[') && trimmed.ends_with(']'))
        {
            if let Ok(value) = parse_json(trimmed) {
                return Ok(ParsedData::Json(value));
            }
        }

        // JWT (format: xxx.yyy.zzz)
        if trimmed.contains('.') && trimmed.split('.').count() == 3 {
            if let Ok((header, payload)) = decode_jwt_unverified(trimmed) {
                return Ok(ParsedData::Jwt { header, payload });
            }
        }

        // YAML (look for common YAML indicators)
        if trimmed.contains(":\n") || trimmed.contains(": ") || trimmed.starts_with("---") {
            if let Ok(value) = parse_yaml(trimmed) {
                return Ok(ParsedData::Yaml(value));
            }
        }

        // TOML (look for [sections] or key = value)
        if trimmed.contains('[') && trimmed.contains(']') && trimmed.contains('=') {
            if let Ok(value) = parse_toml(trimmed) {
                return Ok(ParsedData::Toml(value));
            }
        }

        // XML
        if trimmed.starts_with('<') && trimmed.contains('>') {
            return Ok(ParsedData::Xml(trimmed.to_string()));
        }

        // application/x-www-form-urlencoded (e.g. `a=1&b=hello%20world`)
        if trimmed.contains('=')
            && trimmed.contains('&')
            && !trimmed.contains(char::is_whitespace)
        {
            if let Some(value) = parse_form_urlencoded(trimmed) {
                return Ok(ParsedData::Form(value));
            }
        }

        // Bencode is ASCII, so it has to be tried before the plain-text
        // catch-all below or it would always be reported as text.
        let first = trimmed.as_bytes().first();
        if matches!(first, Some(b'd' | b'l' | b'i'))
            || first.is_some_and(u8::is_ascii_digit)
        {
            if let Ok(value) = decode_bencode(trimmed.as_bytes()) {
                return Ok(ParsedData::Bencode(value));
            }
        }

        // Plain text
        if is_printable_ascii(buf) || is_valid_utf8(buf) {
            return Ok(ParsedData::Text(text.to_string()));
        }
    }

    // Try binary formats

    // MsgPack - try to decode
    if let Ok(value) = decode_msgpack(buf) {
        return Ok(ParsedData::MsgPack(value));
    }

    // CBOR - try to decode
    if let Ok(value) = decode_cbor(buf) {
        return Ok(ParsedData::Cbor(value));
    }

    // BSON - try to decode
    if let Ok(value) = decode_bson(buf) {
        return Ok(ParsedData::Bson(value));
    }

    // Bencode (BitTorrent / DHT). Strict: must consume the whole buffer.
    if let Ok(value) = decode_bencode(buf) {
        return Ok(ParsedData::Bencode(value));
    }

    // Protocol Buffers (schemaless). Strict: every byte must parse as a
    // valid wire-format field, which keeps random data from matching.
    if let Ok(value) = decode_protobuf_value(buf) {
        return Ok(ParsedData::Protobuf(value));
    }

    // LZ4 - no magic bytes, but try decompression
    if let Ok(decompressed) = decompress_lz4(buf) {
        return Ok(ParsedData::Compressed {
            format: "lz4".to_string(),
            decompressed,
        });
    }

    // Raw deflate / brotli have no magic bytes, so only accept them when the
    // result is itself valid UTF-8 — otherwise almost anything "decompresses"
    // into garbage and we'd mislabel plain binary.
    if let Ok(decompressed) = decompress_deflate(buf) {
        if !decompressed.is_empty() && is_valid_utf8(&decompressed) {
            return Ok(ParsedData::Compressed {
                format: "deflate".to_string(),
                decompressed,
            });
        }
    }
    if let Ok(decompressed) = decompress_brotli(buf) {
        if !decompressed.is_empty() && is_valid_utf8(&decompressed) {
            return Ok(ParsedData::Compressed {
                format: "brotli".to_string(),
                decompressed,
            });
        }
    }

    // Detect by magic bytes for known formats
    let format = detect_format(buf);
    Ok(ParsedData::Binary {
        format: format.to_string(),
        data: buf.to_vec(),
    })
}

/// Auto-parse and convert to JSON if possible
pub fn auto_parse_to_json(buf: &[u8]) -> Result<Value> {
    match auto_parse(buf)? {
        ParsedData::Json(v) => Ok(v),
        ParsedData::MsgPack(v) => Ok(v),
        ParsedData::Cbor(v) => Ok(v),
        ParsedData::Bson(v) => Ok(v),
        ParsedData::Bencode(v) => Ok(v),
        ParsedData::Protobuf(v) => Ok(v),
        ParsedData::Form(v) => Ok(v),
        ParsedData::Yaml(v) => Ok(v),
        ParsedData::Toml(v) => Ok(v),
        ParsedData::Jwt { header, payload } => Ok(serde_json::json!({
            "header": header,
            "payload": payload
        })),
        ParsedData::Text(s) => Ok(Value::String(s)),
        ParsedData::Xml(s) => Ok(Value::String(s)),
        ParsedData::Compressed {
            format,
            decompressed,
        } => {
            // Try to parse decompressed data recursively
            if let Ok(value) = auto_parse_to_json(&decompressed) {
                Ok(serde_json::json!({
                    "compressed_format": format,
                    "decompressed_data": value
                }))
            } else {
                Ok(serde_json::json!({
                    "compressed_format": format,
                    "decompressed_size": decompressed.len(),
                    "decompressed_base64": encode_base64(&decompressed)
                }))
            }
        }
        ParsedData::Binary { format, data } => Ok(serde_json::json!({
            "format": format,
            "size": data.len(),
            "base64": encode_base64(&data),
            "hex": encode_hex(&data[..data.len().min(256)])
        })),
    }
}

/// Get a human-readable description of the parsed data
pub fn describe_parsed_data(parsed: &ParsedData) -> String {
    match parsed {
        ParsedData::Json(_) => "JSON document".to_string(),
        ParsedData::MsgPack(_) => "MessagePack binary data".to_string(),
        ParsedData::Cbor(_) => "CBOR binary data".to_string(),
        ParsedData::Bson(_) => "BSON document".to_string(),
        ParsedData::Bencode(_) => "Bencoded data (BitTorrent)".to_string(),
        ParsedData::Protobuf(_) => "Protocol Buffers (schemaless)".to_string(),
        ParsedData::Form(_) => "URL-encoded form data".to_string(),
        ParsedData::Yaml(_) => "YAML document".to_string(),
        ParsedData::Toml(_) => "TOML configuration".to_string(),
        ParsedData::Xml(_) => "XML document".to_string(),
        ParsedData::Jwt { .. } => "JWT token".to_string(),
        ParsedData::Text(s) => format!("Plain text ({} chars)", s.len()),
        ParsedData::Compressed {
            format,
            decompressed,
        } => {
            format!(
                "{} compressed data ({} bytes decompressed)",
                format,
                decompressed.len()
            )
        }
        ParsedData::Binary { format, data } => {
            format!("{} binary data ({} bytes)", format, data.len())
        }
    }
}

impl Display for ParsedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ParsedData::Json(e) => e.to_string(),
            ParsedData::MsgPack(e) => e.to_string(),
            ParsedData::Cbor(e) => e.to_string(),
            ParsedData::Bson(e) => e.to_string(),
            ParsedData::Bencode(e) => e.to_string(),
            ParsedData::Protobuf(e) => e.to_string(),
            ParsedData::Form(e) => e.to_string(),
            ParsedData::Yaml(e) => e.to_string(),
            ParsedData::Toml(e) => e.to_string(),
            ParsedData::Xml(e) => e.to_string(),
            ParsedData::Jwt { header, payload } => {
                format!("{{\"header\":{},\"payload\":{}}}", header, payload)
            }
            ParsedData::Text(e) => e.to_string(),
            ParsedData::Compressed {
                format,
                decompressed,
            } => {
                format!(
                    "{{\"compressed_format\":{},\"decompressed_size\":{}}}",
                    format,
                    decompressed.len()
                )
            }
            ParsedData::Binary { format, data } => {
                format!("{{\"format\":{},\"size\":{}}}", format, data.len())
            }
        };
        write!(f, "{}", str)
    }
}

// ============================================================================
// SERIALIZATION FORMATS
// ============================================================================

/// Try to decode a buffer as MsgPack and return JSON value
pub fn decode_msgpack(buf: &[u8]) -> Result<Value> {
    let v: Value = rmp_serde::from_slice(buf)?;
    Ok(v)
}

/// Encode JSON value to MsgPack
pub fn encode_msgpack(value: &Value) -> Result<Vec<u8>> {
    let buf = rmp_serde::to_vec(value)?;
    Ok(buf)
}

/// Try to decode a buffer as CBOR and return JSON value
pub fn decode_cbor(buf: &[u8]) -> Result<Value> {
    let v: Value = serde_cbor::from_slice(buf)?;
    Ok(v)
}

/// Encode JSON value to CBOR
pub fn encode_cbor(value: &Value) -> Result<Vec<u8>> {
    let buf = serde_cbor::to_vec(value)?;
    Ok(buf)
}

/// Try to decode a buffer as BSON and return JSON value
pub fn decode_bson(buf: &[u8]) -> Result<Value> {
    let doc = bson::Document::from_reader(&mut std::io::Cursor::new(buf))?;
    let v: Value = serde_json::to_value(&doc)?;
    Ok(v)
}

/// Encode JSON value to BSON
pub fn encode_bson(value: &Value) -> Result<Vec<u8>> {
    let doc: bson::Document = bson::deserialize_from_bson(bson::serialize_to_bson(value)?)?;
    let mut buf = Vec::new();
    doc.to_writer(&mut buf)?;
    Ok(buf)
}

/// Try to decode a buffer as Protocol Buffers (generic)
pub fn decode_protobuf(buf: &[u8]) -> Result<HashMap<String, Vec<u8>>> {
    // Generic protobuf decoder - returns raw fields
    let mut fields = HashMap::new();
    let mut pos = 0;

    while pos < buf.len() {
        if let Some((tag, wire_type, value, new_pos)) = parse_protobuf_field(&buf[pos..]) {
            fields.insert(format!("field_{}", tag), value);
            pos += new_pos;
        } else {
            break;
        }
    }

    Ok(fields)
}

/// Parse a single protobuf field
fn parse_protobuf_field(buf: &[u8]) -> Option<(u64, u8, Vec<u8>, usize)> {
    if buf.is_empty() {
        return None;
    }

    let (tag_wire, len1) = decode_varint(buf)?;
    let tag = tag_wire >> 3;
    let wire_type = (tag_wire & 0x07) as u8;

    match wire_type {
        0 => {
            let (value, len2) = decode_varint(&buf[len1..])?;
            Some((tag, wire_type, value.to_le_bytes().to_vec(), len1 + len2))
        }
        2 => {
            let (length, len2) = decode_varint(&buf[len1..])?;
            let start = len1 + len2;
            let end = start + length as usize;
            if end <= buf.len() {
                Some((tag, wire_type, buf[start..end].to_vec(), end))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Decode protobuf varint
fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0;

    for (i, &byte) in buf.iter().enumerate() {
        if i >= 10 {
            return None;
        }
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }

    None
}

/// Try to decode a buffer as Avro
pub fn decode_avro(buf: &[u8]) -> Result<Value> {
    // Simplified avro decoder - would need schema in real world
    anyhow::bail!("Avro decoding requires schema")
}

// ============================================================================
// TEXT ENCODINGS
// ============================================================================

/// Decode base64 string to bytes
pub fn decode_base64(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine};
    let bytes = general_purpose::STANDARD.decode(s)?;
    Ok(bytes)
}

/// Encode bytes to base64 string
pub fn encode_base64(buf: &[u8]) -> String {
    use base64::{engine::general_purpose, Engine};
    general_purpose::STANDARD.encode(buf)
}

/// Decode base64 URL-safe string to bytes
pub fn decode_base64url(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine};
    let bytes = general_purpose::URL_SAFE.decode(s)?;
    Ok(bytes)
}

/// Encode bytes to base64 URL-safe string
pub fn encode_base64url(buf: &[u8]) -> String {
    use base64::{engine::general_purpose, Engine};
    general_purpose::URL_SAFE.encode(buf)
}

/// Decode hex string to bytes
pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(s)?;
    Ok(bytes)
}

/// Encode bytes to hex string
pub fn encode_hex(buf: &[u8]) -> String {
    hex::encode(buf)
}

/// Try to decode URL-encoded string
pub fn decode_url(s: &str) -> Result<String> {
    let decoded = urlencoding::decode(s)?;
    Ok(decoded.to_string())
}

/// Encode string to URL-encoded format
pub fn encode_url(s: &str) -> String {
    urlencoding::encode(s).to_string()
}

/// Decode HTML entities
pub fn decode_html_entities(s: &str) -> String {
    html_escape::decode_html_entities(s).to_string()
}

/// Encode string to HTML entities
pub fn encode_html_entities(s: &str) -> String {
    html_escape::encode_text(s).to_string()
}

// ============================================================================
// COMPRESSION
// ============================================================================

/// Decompress gzip data
pub fn decompress_gzip(buf: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let mut decoder = GzDecoder::new(buf);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// Compress data with gzip
pub fn compress_gzip(buf: &[u8]) -> Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(buf)?;
    Ok(encoder.finish()?)
}

/// Decompress deflate data
pub fn decompress_deflate(buf: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    let mut decoder = DeflateDecoder::new(buf);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// Compress data with deflate
pub fn compress_deflate(buf: &[u8]) -> Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(buf)?;
    Ok(encoder.finish()?)
}

/// Decompress brotli data
pub fn decompress_brotli(buf: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;

    let mut decompressed = Vec::new();
    let mut decoder = brotli::Decompressor::new(buf, 4096);
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// Compress data with brotli
pub fn compress_brotli(buf: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;

    let mut compressed = Vec::new();
    let mut encoder = brotli::CompressorWriter::new(&mut compressed, 4096, 11, 22);
    encoder.write_all(buf)?;
    encoder.flush()?;
    drop(encoder);
    Ok(compressed)
}

/// Decompress zstd data
pub fn decompress_zstd(buf: &[u8]) -> Result<Vec<u8>> {
    let decompressed = zstd::bulk::decompress(buf, 10 * 1024 * 1024)?;
    Ok(decompressed)
}

/// Compress data with zstd
pub fn compress_zstd(buf: &[u8], level: i32) -> Result<Vec<u8>> {
    let compressed = zstd::bulk::compress(buf, level)?;
    Ok(compressed)
}

/// Decompress lz4 data
pub fn decompress_lz4(buf: &[u8]) -> Result<Vec<u8>> {
    let decompressed = lz4_flex::decompress_size_prepended(buf)?;
    Ok(decompressed)
}

/// Compress data with lz4
pub fn compress_lz4(buf: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(buf)
}

/// Decompress bzip2 data
pub fn decompress_bzip2(buf: &[u8]) -> Result<Vec<u8>> {
    use bzip2::read::BzDecoder;
    use std::io::Read;

    let mut decoder = BzDecoder::new(buf);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// Compress data with bzip2
pub fn compress_bzip2(buf: &[u8]) -> Result<Vec<u8>> {
    use bzip2::read::BzEncoder;
    use bzip2::Compression;
    use std::io::Read;

    let mut encoder = BzEncoder::new(buf, Compression::default());
    let mut compressed = Vec::new();
    encoder.read_to_end(&mut compressed)?;
    Ok(compressed)
}

// ============================================================================
// BENCODE (BitTorrent / DHT)
// ============================================================================

/// Decode a bencoded buffer. Strict: the whole buffer must be consumed.
pub fn decode_bencode(buf: &[u8]) -> Result<Value> {
    let mut pos = 0;
    let value = bencode_value(buf, &mut pos)?;
    if pos != buf.len() {
        anyhow::bail!("trailing bytes after bencode value");
    }
    Ok(value)
}

fn bencode_value(buf: &[u8], pos: &mut usize) -> Result<Value> {
    match buf.get(*pos) {
        Some(b'i') => {
            // i<integer>e
            *pos += 1;
            let end = buf[*pos..]
                .iter()
                .position(|&b| b == b'e')
                .ok_or_else(|| anyhow::anyhow!("unterminated bencode integer"))?;
            let num: i64 = std::str::from_utf8(&buf[*pos..*pos + end])?.parse()?;
            *pos += end + 1;
            Ok(Value::from(num))
        }
        Some(b'l') => {
            // l<items>e
            *pos += 1;
            let mut items = Vec::new();
            while buf.get(*pos) != Some(&b'e') {
                if *pos >= buf.len() {
                    anyhow::bail!("unterminated bencode list");
                }
                items.push(bencode_value(buf, pos)?);
            }
            *pos += 1;
            Ok(Value::Array(items))
        }
        Some(b'd') => {
            // d<key><value>...e  (keys are byte strings)
            *pos += 1;
            let mut map = serde_json::Map::new();
            while buf.get(*pos) != Some(&b'e') {
                if *pos >= buf.len() {
                    anyhow::bail!("unterminated bencode dict");
                }
                let key = bencode_byte_string(buf, pos)?;
                let key = String::from_utf8_lossy(&key).into_owned();
                let value = bencode_value(buf, pos)?;
                map.insert(key, value);
            }
            *pos += 1;
            Ok(Value::Object(map))
        }
        Some(c) if c.is_ascii_digit() => {
            let bytes = bencode_byte_string(buf, pos)?;
            match String::from_utf8(bytes.clone()) {
                Ok(s) => Ok(Value::String(s)),
                Err(_) => Ok(serde_json::json!({ "bytes_base64": encode_base64(&bytes) })),
            }
        }
        _ => anyhow::bail!("invalid bencode marker"),
    }
}

fn bencode_byte_string(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    let colon = buf[*pos..]
        .iter()
        .position(|&b| b == b':')
        .ok_or_else(|| anyhow::anyhow!("invalid bencode string length"))?;
    let len: usize = std::str::from_utf8(&buf[*pos..*pos + colon])?.parse()?;
    let start = *pos + colon + 1;
    let end = start
        .checked_add(len)
        .filter(|&e| e <= buf.len())
        .ok_or_else(|| anyhow::anyhow!("bencode string out of bounds"))?;
    *pos = end;
    Ok(buf[start..end].to_vec())
}

// ============================================================================
// FORM URL-ENCODED
// ============================================================================

/// Parse an `application/x-www-form-urlencoded` body into a JSON object.
pub fn parse_form_urlencoded(s: &str) -> Option<Value> {
    let mut map = serde_json::Map::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let key = it.next()?;
        if key.is_empty() {
            return None;
        }
        let raw_val = it.next().unwrap_or("");
        let key = urlencoding::decode(key)
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| key.to_string());
        let val = urlencoding::decode(raw_val)
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| raw_val.to_string());
        map.insert(key, Value::String(val));
    }
    if map.is_empty() {
        None
    } else {
        Some(Value::Object(map))
    }
}

// ============================================================================
// PROTOBUF (schemaless, strict)
// ============================================================================

/// Decode protobuf wire format without a schema. Requires every byte to be a
/// valid field so random binary doesn't get mislabeled as protobuf.
pub fn decode_protobuf_value(buf: &[u8]) -> Result<Value> {
    if buf.is_empty() {
        anyhow::bail!("empty protobuf buffer");
    }

    let mut map = serde_json::Map::new();
    let mut pos = 0;
    let mut fields = 0;

    while pos < buf.len() {
        let (tag_wire, l1) =
            decode_varint(&buf[pos..]).ok_or_else(|| anyhow::anyhow!("bad tag"))?;
        let field = tag_wire >> 3;
        let wire_type = (tag_wire & 0x07) as u8;
        pos += l1;

        let value = match wire_type {
            0 => {
                let (v, l) = decode_varint(&buf[pos..])
                    .ok_or_else(|| anyhow::anyhow!("bad varint"))?;
                pos += l;
                serde_json::json!({ "varint": v })
            }
            1 => {
                if pos + 8 > buf.len() {
                    anyhow::bail!("short 64-bit field");
                }
                let v = encode_hex(&buf[pos..pos + 8]);
                pos += 8;
                serde_json::json!({ "fixed64_hex": v })
            }
            2 => {
                let (len, l) = decode_varint(&buf[pos..])
                    .ok_or_else(|| anyhow::anyhow!("bad length"))?;
                pos += l;
                let end = pos + len as usize;
                if end > buf.len() {
                    anyhow::bail!("length-delimited field out of bounds");
                }
                let bytes = &buf[pos..end];
                pos = end;
                match std::str::from_utf8(bytes) {
                    Ok(s) if is_printable_ascii(bytes) || is_valid_utf8(bytes) => {
                        serde_json::json!({ "string": s })
                    }
                    _ => serde_json::json!({ "bytes_hex": encode_hex(bytes) }),
                }
            }
            5 => {
                if pos + 4 > buf.len() {
                    anyhow::bail!("short 32-bit field");
                }
                let v = encode_hex(&buf[pos..pos + 4]);
                pos += 4;
                serde_json::json!({ "fixed32_hex": v })
            }
            _ => anyhow::bail!("unsupported wire type {}", wire_type),
        };

        let key = format!("field_{}", field);
        match map.get_mut(&key) {
            Some(Value::Array(arr)) => arr.push(value),
            Some(existing) => {
                let prev = existing.take();
                *existing = Value::Array(vec![prev, value]);
            }
            None => {
                map.insert(key, value);
            }
        }
        fields += 1;
    }

    if fields == 0 {
        anyhow::bail!("no protobuf fields");
    }
    Ok(Value::Object(map))
}

// ============================================================================
// JSON UTILITIES
// ============================================================================

/// Try to parse JSON from string
pub fn parse_json(s: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(s)?;
    Ok(v)
}

/// Try to parse JSON from bytes
pub fn parse_json_bytes(buf: &[u8]) -> Result<Value> {
    let v: Value = serde_json::from_slice(buf)?;
    Ok(v)
}

/// Convert JSON to pretty-printed string
pub fn json_to_pretty_string(value: &Value) -> Result<String> {
    let s = serde_json::to_string_pretty(value)?;
    Ok(s)
}

/// Convert JSON to compact string
pub fn json_to_string(value: &Value) -> Result<String> {
    let s = serde_json::to_string(value)?;
    Ok(s)
}

/// Minify JSON string
pub fn minify_json(s: &str) -> Result<String> {
    let v: Value = serde_json::from_str(s)?;
    let minified = serde_json::to_string(&v)?;
    Ok(minified)
}

// ============================================================================
// XML UTILITIES
// ============================================================================

/// Try to parse XML to JSON-like structure
pub fn parse_xml(s: &str) -> Result<String> {
    // Using quick-xml or similar, convert to JSON representation
    // This is a simplified version
    anyhow::bail!("XML parsing not fully implemented")
}

/// Convert XML string to pretty format
pub fn prettify_xml(s: &str) -> Result<String> {
    anyhow::bail!("XML prettify not fully implemented")
}

// ============================================================================
// YAML UTILITIES
// ============================================================================

/// Parse YAML to JSON value
pub fn parse_yaml(s: &str) -> Result<Value> {
    let v: Value = serde_yaml::from_str(s)?;
    Ok(v)
}

/// Convert JSON value to YAML string
pub fn json_to_yaml(value: &Value) -> Result<String> {
    let s = serde_yaml::to_string(value)?;
    Ok(s)
}

// ============================================================================
// TOML UTILITIES
// ============================================================================

/// Parse TOML to JSON value
pub fn parse_toml(s: &str) -> Result<Value> {
    let v: toml::Value = toml::from_str(s)?;
    let json: Value = serde_json::to_value(v)?;
    Ok(json)
}

/// Convert JSON value to TOML string
pub fn json_to_toml(value: &Value) -> Result<String> {
    let toml_value: toml::Value = serde_json::from_value(value.clone())?;
    let s = toml::to_string(&toml_value)?;
    Ok(s)
}

// ============================================================================
// BINARY UTILITIES
// ============================================================================

/// Convert bytes to binary string representation
pub fn bytes_to_binary_string(buf: &[u8]) -> String {
    buf.iter()
        .map(|b| format!("{:08b}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse binary string to bytes
pub fn binary_string_to_bytes(s: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for chunk in s.split_whitespace() {
        if chunk.len() != 8 {
            anyhow::bail!("Invalid binary string format");
        }
        let byte = u8::from_str_radix(chunk, 2)?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Convert bytes to octal string
pub fn bytes_to_octal(buf: &[u8]) -> String {
    buf.iter()
        .map(|b| format!("{:03o}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

// ============================================================================
// JWT UTILITIES
// ============================================================================

/// Decode JWT without verification (extract header and payload)
pub fn decode_jwt_unverified(token: &str) -> Result<(Value, Value)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("Invalid JWT format");
    }

    let header = decode_base64url(parts[0])?;
    let payload = decode_base64url(parts[1])?;

    let header_json: Value = serde_json::from_slice(&header)?;
    let payload_json: Value = serde_json::from_slice(&payload)?;

    Ok((header_json, payload_json))
}

// ============================================================================
// HASH UTILITIES
// ============================================================================

/// Calculate MD5 hash
pub fn hash_md5(buf: &[u8]) -> String {
    format!("{:x}", md5::compute(buf))
}

/// Calculate SHA1 hash
pub fn hash_sha1(buf: &[u8]) -> String {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(buf);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Calculate SHA256 hash
pub fn hash_sha256(buf: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(buf);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Calculate SHA512 hash
pub fn hash_sha512(buf: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha512::new();
    hasher.update(buf);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Calculate Blake2b hash
pub fn hash_blake2b(buf: &[u8]) -> String {
    use blake2::{Blake2b512, Digest};
    let mut hasher = Blake2b512::new();
    hasher.update(buf);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Calculate CRC32
pub fn hash_crc32(buf: &[u8]) -> u32 {
    crc32fast::hash(buf)
}

// ============================================================================
// CHARACTER ENCODING
// ============================================================================

/// Detect and decode various character encodings to UTF-8
pub fn decode_to_utf8(buf: &[u8], encoding: &str) -> Result<String> {
    match encoding.to_lowercase().as_str() {
        "utf-8" | "utf8" => Ok(String::from_utf8(buf.to_vec())?),
        "ascii" => Ok(String::from_utf8_lossy(buf).to_string()),
        "latin1" | "iso-8859-1" => Ok(buf.iter().map(|&b| b as char).collect()),
        _ => anyhow::bail!("Unsupported encoding: {}", encoding),
    }
}

/// Try to detect if buffer is valid UTF-8
pub fn is_valid_utf8(buf: &[u8]) -> bool {
    std::str::from_utf8(buf).is_ok()
}

/// Try to detect if buffer is printable ASCII
pub fn is_printable_ascii(buf: &[u8]) -> bool {
    buf.iter()
        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
}

// ============================================================================
// MIME/MULTIPART UTILITIES
// ============================================================================

/// Parse Content-Type header
pub fn parse_content_type(header: &str) -> Result<(String, HashMap<String, String>)> {
    let parts: Vec<&str> = header.splitn(2, ';').collect();
    let mime_type = parts[0].trim().to_lowercase();

    let mut params = HashMap::new();
    if parts.len() > 1 {
        for param in parts[1].split(';') {
            if let Some((key, value)) = param.split_once('=') {
                params.insert(
                    key.trim().to_lowercase(),
                    value.trim().trim_matches('"').to_string(),
                );
            }
        }
    }

    Ok((mime_type, params))
}

// ============================================================================
// NETWORK UTILITIES
// ============================================================================

/// Parse IPv4 address from bytes
pub fn parse_ipv4(buf: &[u8]) -> Result<String> {
    if buf.len() != 4 {
        anyhow::bail!("Invalid IPv4 address length");
    }
    Ok(format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]))
}

/// Parse IPv6 address from bytes
pub fn parse_ipv6(buf: &[u8]) -> Result<String> {
    if buf.len() != 16 {
        anyhow::bail!("Invalid IPv6 address length");
    }

    let parts: Vec<String> = buf
        .chunks(2)
        .map(|chunk| format!("{:02x}{:02x}", chunk[0], chunk[1]))
        .collect();

    Ok(parts.join(":"))
}

/// Parse MAC address from bytes
pub fn parse_mac_address(buf: &[u8]) -> Result<String> {
    if buf.len() != 6 {
        anyhow::bail!("Invalid MAC address length");
    }

    Ok(buf
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":"))
}

// ============================================================================
// TIME UTILITIES
// ============================================================================

/// Parse Unix timestamp (seconds)
pub fn parse_unix_timestamp(timestamp: i64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp(timestamp, 0);
    dt.map(|d| d.to_rfc3339())
        .unwrap_or_else(|| "Invalid timestamp".to_string())
}

/// Parse Unix timestamp (milliseconds)
pub fn parse_unix_timestamp_ms(timestamp: i64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp_millis(timestamp);
    dt.map(|d| d.to_rfc3339())
        .unwrap_or_else(|| "Invalid timestamp".to_string())
}

// ============================================================================
// STRING UTILITIES
// ============================================================================

/// Escape string for JSON
pub fn escape_json_string(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            '\t' => vec!['\\', 't'],
            c => vec![c],
        })
        .collect()
}

/// Unescape JSON string
pub fn unescape_json_string(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                result.push(match next {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    _ => next,
                });
            }
        } else {
            result.push(c);
        }
    }

    result
}

// ============================================================================
// DATA FORMAT DETECTION
// ============================================================================

/// Try to detect data format from magic bytes
pub fn detect_format(buf: &[u8]) -> &'static str {
    if buf.is_empty() {
        return "empty";
    }

    // Magic bytes detection
    if buf.len() >= 2 {
        match &buf[0..2] {
            [0x1f, 0x8b] => return "gzip",
            [0x42, 0x5a] => return "bzip2",
            [0x50, 0x4b] => return "zip",
            _ => {}
        }
    }

    if buf.len() >= 4 {
        match &buf[0..4] {
            [0x89, 0x50, 0x4e, 0x47] => return "png",
            [0xff, 0xd8, 0xff, _] => return "jpeg",
            [0x25, 0x50, 0x44, 0x46] => return "pdf",
            [0x28, 0xb5, 0x2f, 0xfd] => return "zstd",
            _ => {}
        }
    }

    // Try JSON
    if let Ok(_) = serde_json::from_slice::<Value>(buf) {
        return "json";
    }

    // Try UTF-8 text
    if is_valid_utf8(buf) {
        return "text";
    }

    "binary"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bencode_dict_and_list() {
        // d 4:spam l 1:a 1:b e e  ->  {"spam": ["a","b"]}
        let v = decode_bencode(b"d4:spaml1:a1:bee").unwrap();
        assert_eq!(v, serde_json::json!({ "spam": ["a", "b"] }));
        assert_eq!(decode_bencode(b"i42e").unwrap(), serde_json::json!(42));
        // Trailing garbage must be rejected (strictness).
        assert!(decode_bencode(b"i42eX").is_err());
    }

    #[test]
    fn form_urlencoded() {
        let v = parse_form_urlencoded("a=1&b=hello%20world&c=").unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "a": "1", "b": "hello world", "c": "" })
        );
    }

    #[test]
    fn protobuf_string_field() {
        // field 1, wire type 2 (len-delimited), "test"
        let buf = [0x0a, 0x04, b't', b'e', b's', b't'];
        let v = decode_protobuf_value(&buf).unwrap();
        assert_eq!(v, serde_json::json!({ "field_1": { "string": "test" } }));
    }

    #[test]
    fn bzip2_roundtrip() {
        let data = b"DeepTrace bzip2 roundtrip payload, repeated repeated repeated";
        let comp = compress_bzip2(data).unwrap();
        assert_eq!(decompress_bzip2(&comp).unwrap(), data);
    }

    #[test]
    fn auto_parse_routes_new_formats() {
        match auto_parse(b"d3:foo3:bare").unwrap() {
            ParsedData::Bencode(_) => {}
            other => panic!("expected Bencode, got {other:?}"),
        }
        match auto_parse(b"x=1&y=2").unwrap() {
            ParsedData::Form(_) => {}
            other => panic!("expected Form, got {other:?}"),
        }
    }
}
