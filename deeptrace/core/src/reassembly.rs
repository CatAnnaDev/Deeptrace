/// Very small TCP stream reassembly primitive (placeholder)
pub struct StreamReassembler;

impl StreamReassembler {
    pub fn new() -> Self { StreamReassembler }
    pub fn push_segment(&mut self, _seq: u64, _data: &[u8]) {}
    pub fn take_stream(&mut self) -> Option<Vec<u8>> { None }
}
