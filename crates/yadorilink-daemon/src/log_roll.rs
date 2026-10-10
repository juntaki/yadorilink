//! Size-capped rolling log file for the macOS LaunchAgent.
//!
//! launchd's `StandardOutPath` files are never rotated. When
//! `YADORILINK_LOG_FILE` is set, the daemon logs there instead: once the file
//! passes [`MAX_BYTES`] it is renamed to `<file>.1` (replacing the previous
//! one) and a fresh file is started, so at most about 2 * MAX_BYTES is kept.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub const MAX_BYTES: u64 = 10 * 1024 * 1024;

struct Inner {
    path: PathBuf,
    file: File,
    len: u64,
    max: u64,
}

#[derive(Clone)]
pub struct RollingLog(Arc<Mutex<Inner>>);

impl RollingLog {
    pub fn open(path: PathBuf, max: u64) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let len = file.metadata()?.len();
        Ok(Self(Arc::new(Mutex::new(Inner { path, file, len, max }))))
    }
}

impl Write for &RollingLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if g.len >= g.max {
            let mut rolled = g.path.clone().into_os_string();
            rolled.push(".1");
            // Best effort: on failure keep appending to the current file.
            if fs::rename(&g.path, &rolled).is_ok() {
                if let Ok(f) = OpenOptions::new().create(true).append(true).open(&g.path) {
                    g.file = f;
                    g.len = 0;
                }
            }
        }
        let n = g.file.write(buf)?;
        g.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).file.flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RollingLog {
    type Writer = &'a RollingLog;
    fn make_writer(&'a self) -> Self::Writer {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolls_once_past_the_cap() {
        let dir = std::env::temp_dir().join(format!("ylog-roll-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("daemon.log");
        let log = RollingLog::open(path.clone(), 10).unwrap();
        (&log).write_all(b"0123456789").unwrap();
        (&log).write_all(b"abc").unwrap();
        assert_eq!(fs::read(dir.join("daemon.log.1")).unwrap(), b"0123456789");
        assert_eq!(fs::read(&path).unwrap(), b"abc");
        fs::remove_dir_all(dir).unwrap();
    }
}
