//! A minimal stderr spinner for long scans.
//!
//! It renders only when stderr is an interactive terminal, so it writes
//! nothing when output is piped or running in CI — machine output
//! (json/sarif on stdout) is never touched. The spinner lives entirely
//! on stderr and clears itself when dropped.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use leakferret_core::ScanProgress;

const FRAMES: [char; 4] = ['|', '/', '-', '\\'];
const TICK: Duration = Duration::from_millis(90);

/// RAII handle for the spinner thread. Dropping it stops the thread and
/// clears the line, so the report below it starts on a clean row.
pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Spinner {
    /// Start a spinner driven by `progress`. A no-op (renders nothing)
    /// when stderr is not a terminal.
    pub fn start(progress: Arc<ScanProgress>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        if !std::io::stderr().is_terminal() {
            return Self { stop, handle: None };
        }
        let stop_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut err = std::io::stderr();
            let mut frame = 0usize;
            while !stop_thread.load(Ordering::Relaxed) {
                let total = progress.total.load(Ordering::Relaxed);
                let scanned = progress.scanned.load(Ordering::Relaxed);
                let spin = FRAMES[frame % FRAMES.len()];
                let _ = if total == 0 {
                    write!(err, "\r  {spin} walking the tree...")
                } else {
                    write!(err, "\r  {spin} scanning {scanned}/{total} files")
                };
                let _ = err.flush();
                frame += 1;
                thread::sleep(TICK);
            }
            // Wipe the spinner line so the report starts clean.
            let _ = write!(err, "\r{:<50}\r", "");
            let _ = err.flush();
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
