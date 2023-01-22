use byteorder::{ReadBytesExt, WriteBytesExt, LE};

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

pub trait WriteExt {
    fn write_bool(&mut self, value: bool) -> Result<(), super::Error>;
    fn write_string(&mut self, value: &str) -> Result<(), super::Error>;
}

impl<R: std::io::Read> ReadExt for R {
    fn read_bool(&mut self) -> Result<bool, super::Error> {
        match self.read_u8()? {
            1 => Ok(true),
            0 => Ok(false),
            err => Err(super::Error::Bool(err)),
        }
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

    fn read_string(&mut self) -> Result<String, super::Error> {
        let mut buf = match self.read_i32::<LE>()? {
            size if size.is_negative() => {
                let mut buf = Vec::with_capacity(-size as usize);
                for _ in 0..buf.capacity() {
                    buf.push(self.read_u16::<LE>()?);
                }
                String::from_utf16(&buf)?
            }
            size => String::from_utf8(self.read_len(size as usize)?)?,
        };
        // remove the null byte
        buf.pop();
        Ok(buf)
    }

    fn read_len(&mut self, len: usize) -> Result<Vec<u8>, super::Error> {
        let mut buf = vec![0; len];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl<W: std::io::Write> WriteExt for W {
    fn write_bool(&mut self, value: bool) -> Result<(), super::Error> {
        self.write_u8(match value {
            true => 1,
            false => 0,
        })?;
        Ok(())
    }
    fn write_string(&mut self, value: &str) -> Result<(), super::Error> {
        let bytes = value.as_bytes();
        self.write_u32::<LE>(bytes.len() as u32 + 1)?;
        self.write_all(bytes)?;
        self.write_u8(0)?;
        Ok(())
    }
}
