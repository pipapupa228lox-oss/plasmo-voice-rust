//! Byte helpers matching the Java side (`PacketUtil`, Guava's
//! `ByteArrayDataInput/Output`): big-endian integers, `writeUTF`'s unsigned
//! short length, and 16-byte UUIDs as two longs.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Ran out of bytes while reading.
    UnexpectedEnd,
    /// A length field was outside the bound the Java code checks.
    OutOfRange(&'static str, i64),
    /// The first four bytes of a UDP datagram were not the magic number.
    BadMagic(u32),
    /// The packet id is not one this codec knows.
    UnknownPacket(u8),
    /// A string was not valid modified UTF-8.
    BadString,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEnd => write!(f, "unexpected end of packet"),
            Error::OutOfRange(what, value) => write!(f, "{what} out of range: {value}"),
            Error::BadMagic(magic) => write!(f, "not a PlasmoVoice packet (magic {magic:#x})"),
            Error::UnknownPacket(id) => write!(f, "unknown packet id {id:#x}"),
            Error::BadString => write!(f, "string is not modified UTF-8"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// 16 bytes, as `PacketUtil.writeUUID` writes them.
pub type Uuid = [u8; 16];

/// A UUID built the way `UUID.nameUUIDFromBytes` builds one: MD5, version 3,
/// RFC 4122 variant. PlasmoVoice derives activation and line ids this way.
pub fn name_uuid(name: &str) -> Uuid {
    use md5::{Digest, Md5};

    let mut hasher = Md5::new();
    hasher.update(name.as_bytes());
    let mut bytes: Uuid = hasher.finalize().into();

    // Version 3 (name-based, MD5).
    bytes[6] = (bytes[6] & 0x0f) | 0x30;
    // RFC 4122 variant.
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

/// Formats a UUID the Java way: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub fn uuid_to_string(uuid: Uuid) -> String {
    let mut s = String::with_capacity(36);
    for (i, byte) in uuid.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    /// Everything not read yet, consumed.
    pub fn rest(&mut self) -> &'a [u8] {
        let slice = &self.buf[self.pos..];
        self.pos = self.buf.len();
        slice
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.remaining() < count {
            return Err(Error::UnexpectedEnd);
        }
        let slice = &self.buf[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn read_bool(&mut self) -> Result<bool> {
        Ok(self.read_u8()? != 0)
    }

    pub fn read_i16(&mut self) -> Result<i16> {
        let bytes = self.take(2)?;
        Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        let bytes = self.take(4)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_i64(&mut self) -> Result<i64> {
        let bytes = self.take(8)?;
        Ok(i64::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_f64(&mut self) -> Result<f64> {
        Ok(f64::from_bits(self.read_i64()? as u64))
    }

    pub fn read_uuid(&mut self) -> Result<Uuid> {
        let bytes = self.take(16)?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(bytes);
        Ok(uuid)
    }

    /// `DataInput.readUTF`: an unsigned short length, then the bytes.
    /// Lengths the Java side bounds with `readSafeUTF` are checked here too.
    pub fn read_utf(&mut self, max: usize) -> Result<String> {
        let len = self.read_u16()? as usize;
        let bytes = self.take(len)?;
        if len > max {
            return Err(Error::OutOfRange("string length", len as i64));
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::BadString)
    }

    /// `PacketUtil.readSafeInt(in, min, max)`.
    pub fn read_safe_int(&mut self, min: i32, max: i32, what: &'static str) -> Result<i32> {
        let value = self.read_i32()?;
        if value < min || value > max {
            return Err(Error::OutOfRange(what, value as i64));
        }
        Ok(value)
    }

    /// `PacketUtil.readBytes`: `readSafeInt(in, 1, max)`, then the bytes. An
    /// empty blob is rejected, the way the Java side rejects it.
    pub fn read_bytes(&mut self, max: usize, what: &'static str) -> Result<Vec<u8>> {
        let len = self.read_safe_int(1, max.min(i32::MAX as usize) as i32, what)?;
        Ok(self.take(len as usize)?.to_vec())
    }

    /// `mTU`-sized audio payloads: `BaseAudioPacket.read` uses 1..2048.
    pub fn read_audio(&mut self) -> Result<Vec<u8>> {
        let len = self.read_safe_int(1, 2048, "audio length")?;
        Ok(self.take(len as usize)?.to_vec())
    }

    /// `PacketUtil.readIntList`.
    pub fn read_int_list(&mut self, max_size: usize) -> Result<Vec<i32>> {
        let size = self.read_safe_int(0, max_size as i32, "list size")?;
        let mut out = Vec::with_capacity(size as usize);
        for _ in 0..size {
            out.push(self.read_i32()?);
        }
        Ok(out)
    }

    /// `PacketUtil.readNullableString`.
    pub fn read_nullable_string(&mut self, max: usize) -> Result<Option<String>> {
        if self.read_bool()? {
            Ok(Some(self.read_utf(max)?))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn write_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn write_bool(&mut self, value: bool) {
        self.write_u8(u8::from(value));
    }

    pub fn write_i16(&mut self, value: i16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_i32(&mut self, value: i32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_i64(&mut self, value: i64) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_f64(&mut self, value: f64) {
        self.write_i64(value.to_bits() as i64);
    }

    pub fn write_uuid(&mut self, uuid: Uuid) {
        self.buf.extend_from_slice(&uuid);
    }

    pub fn write_utf(&mut self, value: &str) {
        let bytes = value.as_bytes();
        self.write_u16(bytes.len() as u16);
        self.buf.extend_from_slice(bytes);
    }

    pub fn write_bytes(&mut self, value: &[u8]) {
        self.write_i32(value.len() as i32);
        self.buf.extend_from_slice(value);
    }

    pub fn write_raw(&mut self, value: &[u8]) {
        self.buf.extend_from_slice(value);
    }
}
