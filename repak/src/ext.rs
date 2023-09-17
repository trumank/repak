use byteorder::{ReadBytesExt, WriteBytesExt, LE};

pub trait BoolExt<T, E, F: FnOnce() -> Result<T, E>> {
    fn then_try(&self, f: F) -> Result<Option<T>, E>;
}

impl<T, E, F: FnOnce() -> Result<T, E>> BoolExt<T, E, F> for bool {
    fn then_try(&self, f: F) -> Result<Option<T>, E> {
        self.then(f).transpose()
    }
}

pub trait ReadExt {
    fn read_bool(&mut self) -> Result<bool, super::Error>;
    fn read_guid(&mut self) -> Result<[u8; 20], super::Error>;
    fn read_array<T>(
        &mut self,
        func: impl FnMut(&mut Self) -> Result<T, super::Error>,
    ) -> Result<Vec<T>, super::Error>;
    fn read_array_len<T>(
        &mut self,
        len: usize,
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
        func: impl FnMut(&mut Self) -> Result<T, super::Error>,
    ) -> Result<Vec<T>, super::Error> {
        let len = self.read_u32::<LE>()? as usize;
        self.read_array_len(len, func)
    }

    fn read_array_len<T>(
        &mut self,
        len: usize,
        mut func: impl FnMut(&mut Self) -> Result<T, super::Error>,
    ) -> Result<Vec<T>, super::Error> {
        let mut buf = Vec::with_capacity(len);
        for _ in 0..buf.capacity() {
            buf.push(func(self)?);
        }
        Ok(buf)
    }

    fn read_string(&mut self) -> Result<String, super::Error> {
        let len = self.read_i32::<LE>()?;
        if len < 0 {
            let chars = self.read_array_len((-len) as usize, |r| Ok(r.read_u16::<LE>()?))?;
            let length = chars.iter().position(|&c| c == 0).unwrap_or(chars.len());
            Ok(String::from_utf16(&chars[..length]).unwrap())
        } else {
            let mut chars = vec![0; len as usize];
            self.read_exact(&mut chars)?;
            let length = chars.iter().position(|&c| c == 0).unwrap_or(chars.len());
            Ok(String::from_utf8_lossy(&chars[..length]).into_owned())
        }
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
        if value.is_empty() || value.is_ascii() {
            self.write_u32::<LE>(value.as_bytes().len() as u32 + 1)?;
            self.write_all(value.as_bytes())?;
            self.write_u8(0)?;
        } else {
            let chars: Vec<u16> = value.encode_utf16().collect();
            self.write_i32::<LE>(-(chars.len() as i32 + 1))?;
            for c in chars {
                self.write_u16::<LE>(c)?;
            }
            self.write_u16::<LE>(0)?;
        }
        Ok(())
    }
}
