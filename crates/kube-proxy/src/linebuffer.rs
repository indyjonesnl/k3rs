//! `LineBuffer`: building `iptables-restore` input a line at a time.
//!
//! Ported from `pkg/proxy/util/linebuffer.go` (`LineBuffer`, `realLineBuffer`,
//! `discardLineBuffer`, `NewLineBuffer`, `NewDiscardLineBuffer`).
//!
//! Deviation (Rust idiom): Go's `Write(args ...interface{})` takes strings and
//! `[]string` and panics on any other type ("unknown argument type"). Here the
//! argument is the [`Arg`] enum, so that panic cannot happen.

/// One argument of [`LineBuffer::write`]: a string or a list of strings.
#[derive(Debug, Clone, Copy)]
pub enum Arg<'a> {
    Str(&'a str),
    Slice(&'a [String]),
    Strs(&'a [&'a str]),
}

impl<'a> From<&'a str> for Arg<'a> {
    fn from(s: &'a str) -> Self {
        Arg::Str(s)
    }
}

impl<'a> From<&'a String> for Arg<'a> {
    fn from(s: &'a String) -> Self {
        Arg::Str(s)
    }
}

impl<'a> From<&'a [String]> for Arg<'a> {
    fn from(s: &'a [String]) -> Self {
        Arg::Slice(s)
    }
}

impl<'a> From<&'a Vec<String>> for Arg<'a> {
    fn from(s: &'a Vec<String>) -> Self {
        Arg::Slice(s)
    }
}

impl<'a> From<&'a [&'a str]> for Arg<'a> {
    fn from(s: &'a [&'a str]) -> Self {
        Arg::Strs(s)
    }
}

/// Writing lines of input to a buffer.
pub trait LineBuffer {
    /// Join all the individual strings with spaces, terminate with a newline
    /// and write them to the buffer.
    fn write(&mut self, args: &[Arg<'_>]);
    /// Write bytes to the buffer and terminate with a newline.
    fn write_bytes(&mut self, bytes: &[u8]);
    /// Clear the buffer.
    fn reset(&mut self);
    /// The contents of the buffer.
    fn bytes(&self) -> &[u8];
    /// The contents of the buffer as a string.
    fn string(&self) -> String {
        String::from_utf8_lossy(self.bytes()).into_owned()
    }
    /// The number of times `write` or `write_bytes` was called; it assumes
    /// nothing wrote newlines to the buffer itself.
    fn lines(&self) -> usize;
}

/// `realLineBuffer`.
#[derive(Debug, Default)]
pub struct RealLineBuffer {
    b: Vec<u8>,
    lines: usize,
}

impl RealLineBuffer {
    /// `NewLineBuffer`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl LineBuffer for RealLineBuffer {
    fn write(&mut self, args: &[Arg<'_>]) {
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                self.b.push(b' ');
            }
            match arg {
                Arg::Str(s) => self.b.extend_from_slice(s.as_bytes()),
                Arg::Slice(v) => {
                    for (j, s) in v.iter().enumerate() {
                        if j > 0 {
                            self.b.push(b' ');
                        }
                        self.b.extend_from_slice(s.as_bytes());
                    }
                }
                Arg::Strs(v) => {
                    for (j, s) in v.iter().enumerate() {
                        if j > 0 {
                            self.b.push(b' ');
                        }
                        self.b.extend_from_slice(s.as_bytes());
                    }
                }
            }
        }
        self.b.push(b'\n');
        self.lines += 1;
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.b.extend_from_slice(bytes);
        self.b.push(b'\n');
        self.lines += 1;
    }

    fn reset(&mut self) {
        self.b.clear();
        self.lines = 0;
    }

    fn bytes(&self) -> &[u8] {
        &self.b
    }

    fn lines(&self) -> usize {
        self.lines
    }
}

/// `discardLineBuffer`: counts the writes, throws the data away. Used for
/// iptables proxy partial syncs, to track how many rules did not need syncing.
#[derive(Debug, Default)]
pub struct DiscardLineBuffer {
    lines: usize,
}

impl DiscardLineBuffer {
    /// `NewDiscardLineBuffer`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl LineBuffer for DiscardLineBuffer {
    fn write(&mut self, _args: &[Arg<'_>]) {
        self.lines += 1;
    }

    fn write_bytes(&mut self, _bytes: &[u8]) {
        self.lines += 1;
    }

    fn reset(&mut self) {
        self.lines = 0;
    }

    fn bytes(&self) -> &[u8] {
        &[]
    }

    fn lines(&self) -> usize {
        self.lines
    }
}
