//! Hand-rolled ZIP writer used only by the test suite.
//!
//! The `zip` crate's writer sanitises member names and refuses duplicates, so
//! it cannot produce the very fixtures the security tests need. Writing the
//! records by hand here keeps those tests honest: the container is
//! spec-valid ZIP, and only the *contents* are adversarial.
//!
//! Layout emitted (stored/uncompressed, no data descriptor):
//!
//! ```text
//! for each entry:  local file header (30 + n) | data
//! central directory:  one record per entry (46 + n)
//! end of central directory (22)
//! ```

/// A member to emit, with every field the tests want to control.
#[derive(Debug, Clone)]
pub struct RawMember {
    /// The name exactly as it will appear in the archive.
    pub name: String,
    /// The member's bytes, stored uncompressed.
    pub body: Vec<u8>,
    /// CRC-32 to record. Overriding this is how corrupt-archive tests are made.
    pub crc: u32,
    /// Unix mode to record in the external attributes.
    pub mode: u32,
    /// General-purpose bit flags (bit 0 = encrypted, bit 11 = UTF-8 names).
    pub flags: u16,
}

impl RawMember {
    /// An ordinary, safe member.
    pub fn file(name: &str, body: &[u8]) -> Self {
        Self {
            name: name.to_string(),
            body: body.to_vec(),
            crc: crc32fast::hash(body),
            mode: 0o100644,
            flags: 0x0800,
        }
    }

    /// A member whose name is hostile but whose container is valid.
    pub fn hostile(name: &str, body: &[u8]) -> Self {
        Self {
            name: name.to_string(),
            body: body.to_vec(),
            crc: crc32fast::hash(body),
            mode: 0o100644,
            flags: 0x0800,
        }
    }

    /// Record a wrong CRC, to exercise the integrity check.
    pub fn with_bad_crc(mut self) -> Self {
        self.crc ^= 0xFFFF_FFFF;
        self
    }

    /// Record a symlink's mode, to exercise link handling.
    pub fn into_symlink(mut self) -> Self {
        self.mode = 0o120777;
        self
    }

    /// Mark the member encrypted, without producing a valid ciphertext.
    ///
    /// This is enough to exercise the engine's *routing* of encrypted members:
    /// it will never try to decrypt, only refuse or prompt.
    pub fn into_encrypted(mut self) -> Self {
        self.flags |= 0x0001;
        self.crc = 0;
        self
    }
}

fn u16le(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}

fn u32le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Build a ZIP archive from raw members.
pub fn raw_zip(members: &[RawMember]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    let mut count = 0u16;

    for m in members {
        let offset = out.len() as u32;
        let name = m.name.as_bytes();
        let crc = m.crc;
        let size = m.body.len() as u32;
        let flags = m.flags;

        // Local file header
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&u16le(20)); // version needed
        out.extend_from_slice(&u16le(flags));
        out.extend_from_slice(&u16le(0)); // stored
        out.extend_from_slice(&u16le(0)); // mod time
        out.extend_from_slice(&u16le(0x21)); // mod date (1980-01-01)
        out.extend_from_slice(&u32le(crc));
        out.extend_from_slice(&u32le(size));
        out.extend_from_slice(&u32le(size));
        out.extend_from_slice(&u16le(name.len() as u16));
        out.extend_from_slice(&u16le(0)); // extra length
        out.extend_from_slice(name);
        out.extend_from_slice(&m.body);

        // Central directory record
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&u16le(0x031e)); // version made by: unix, 3.0
        central.extend_from_slice(&u16le(20));
        central.extend_from_slice(&u16le(flags));
        central.extend_from_slice(&u16le(0));
        central.extend_from_slice(&u16le(0));
        central.extend_from_slice(&u16le(0x21));
        central.extend_from_slice(&u32le(crc));
        central.extend_from_slice(&u32le(size));
        central.extend_from_slice(&u32le(size));
        central.extend_from_slice(&u16le(name.len() as u16));
        central.extend_from_slice(&u16le(0)); // extra
        central.extend_from_slice(&u16le(0)); // comment
        central.extend_from_slice(&u16le(0)); // disk number
        central.extend_from_slice(&u16le(0)); // internal attrs
        central.extend_from_slice(&u32le(m.mode << 16));
        central.extend_from_slice(&u32le(offset));
        central.extend_from_slice(name);

        count += 1;
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);

    // End of central directory
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(count));
    out.extend_from_slice(&u16le(count));
    out.extend_from_slice(&u32le(cd_size));
    out.extend_from_slice(&u32le(cd_offset));
    out.extend_from_slice(&u16le(0));

    out
}
