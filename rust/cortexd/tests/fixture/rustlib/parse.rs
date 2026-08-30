pub struct Frame {
    pub len: usize,
}

pub fn parse_str(input: &str) -> Frame {
    Frame { len: input.len() }
}
