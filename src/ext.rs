use byteorder::ReadBytesExt;

pub trait ReadExt {
    fn read_bool(&mut self) -> Result<bool, super::Error>;
    fn read_guid(&mut self) -> Result<[u8; 20], super::Error>;
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

    fn read_len(&mut self, len: usize) -> Result<Vec<u8>, super::Error> {
        let mut buf = Vec::with_capacity(len);
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}
