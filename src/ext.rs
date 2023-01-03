use byteorder::{ReadBytesExt, LE};

type R = dyn std::io::Read;

pub trait ReadExt {
    fn read_bool(&mut self) -> Result<bool, super::Error>;
    fn read_guid(&mut self) -> Result<[u8; 20], super::Error>;
    fn read_array<T>(
        &mut self,
        func: impl FnMut(&mut Self) -> Result<T, super::Error>,
    ) -> Result<Vec<T>, super::Error>;
    fn read_string(&mut self) -> Result<String, super::Error>;
    fn read_len(&mut self, len: usize) -> Result<Vec<u8>, super::Error>;
}

impl<R: std::io::Read> ReadExt for R {
    fn read_bool(&mut self) -> Result<bool, super::Error> {
        Ok(self.read_u8()? != 0)
    }

    fn read_guid(&mut self) -> Result<[u8; 20], super::Error> {
        let mut guid = [0; 20];
        self.read_exact(&mut guid)?;
        Ok(guid)
    }

    fn read_array<T>(
        &mut self,
        mut func: impl FnMut(&mut Self) -> Result<T, super::Error>,
    ) -> Result<Vec<T>, super::Error> {
        let mut buf = Vec::with_capacity(self.read_u32::<LE>()? as usize);
        for _ in 0..buf.capacity() {
            buf.push(func(self)?);
        }
        Ok(buf)
    }

    fn read_string(&mut self) -> Result<String, crate::Error> {
        Ok(match self.read_i32::<LE>()? {
            size if size.is_positive() => String::from_utf8(self.read_len(size as usize)?)?,
            size if size.is_negative() => {
                let size = 2 * -size;
                let mut buf = Vec::with_capacity(size as usize / 2);
                for _ in 0..buf.capacity() {
                    buf.push(self.read_u16::<LE>()?);
                }
                String::from_utf16(&buf)?
            }
            _ => String::new(),
        })
    }

    fn read_len(&mut self, len: usize) -> Result<Vec<u8>, super::Error> {
        let mut buf = Vec::with_capacity(len);
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}
