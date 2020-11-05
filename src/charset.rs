use std::ops::Range;

pub struct Charset(pub Vec<u8>);

impl<T> From<T> for Charset
where
    T: AsRef<str>,
{
    fn from(t: T) -> Self {
        Self(t.as_ref().as_bytes().to_vec())
    }
}

impl AsRef<[u8]> for Charset {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Charset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for c in &self.0 {
            let c = *c as char;
            if c.is_ascii_graphic() {
                write!(f, "{}", c)?;
            } else {
                write!(f, "\\x{:02x}", c as u64)?;
            }
        }
        Ok(())
    }
}

impl Charset {
    pub fn range(&self, output_len: u32) -> Range<u64> {
        0..(self.0.len() as u64).pow(output_len)
    }

    pub fn get_into(&self, i: u64, buf: &mut [u8]) {
        let n = self.0.len() as u64;

        let mut remain = i;
        for slot in buf.iter_mut() {
            let modulo = remain % n;
            *slot = self.0[modulo as usize];
            remain = (remain - modulo) / n;
        }
    }
}
