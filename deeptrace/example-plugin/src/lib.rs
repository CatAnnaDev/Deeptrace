//! Example DeepTrace plugin.
//!
//! It demonstrates the full SDK: a single safe `fn(&[u8]) -> Result<Value>`
//! wired up by `declare_plugin!`. This one is actually useful — it runs the
//! `proto` auto-detection stack (JSON, MsgPack, CBOR, BSON, protobuf,
//! bencode, gzip/zstd/bzip2/lz4, JWT, YAML/TOML, form-urlencoded, …) over the
//! payload and returns a structured summary.

use anyhow::{bail, Result};
use plugins_sdk::declare_plugin;
use proto::msgpack_decoder::{auto_parse, auto_parse_to_json, describe_parsed_data};
use serde_json::{json, Value};

fn decode(data: &[u8]) -> Result<Value> {
    // Skip payloads that are almost certainly framing noise so we act as a
    // real "is this mine?" filter rather than matching everything.
    if data.len() < 2 {
        bail!("payload too small to classify");
    }

    let parsed = auto_parse(data)?;
    let kind = describe_parsed_data(&parsed);

    // Anything that's just opaque/plain bytes isn't interesting here.
    if kind.starts_with("binary") || kind.starts_with("Plain text") {
        bail!("no structured format detected ({kind})");
    }

    let decoded = auto_parse_to_json(data).unwrap_or(Value::Null);
    Ok(json!({
        "plugin": "auto-decode",
        "detected": kind,
        "bytes": data.len(),
        "decoded": decoded,
    }))
}

declare_plugin!(
    "auto-decode",
    "Runs the proto auto-detection stack (JSON, MsgPack, CBOR, BSON, \
     protobuf, bencode, JWT, gzip/zstd/bzip2/lz4, YAML/TOML, form) over \
     the payload and returns a structured summary.",
    decode
);
