use anyhow::Result;
use rmp_serde::from_slice;
use serde_json::Value;

/// Try to decode a buffer as MsgPack and return JSON value
pub fn decode_msgpack(buf: &[u8]) -> Result<Value> {
    let v: Value = from_slice(buf)?;
    Ok(v)
}
