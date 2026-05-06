//! JSON reporter. Serialises [`FindingView`] (raw match stripped) as a
//! pretty-printed array.

use std::io::{self, Write};

use crate::finding::{Finding, FindingView};

use super::Reporter;

#[derive(Debug, Clone, Copy, Default)]
pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn emit<W: Write>(&self, findings: &[Finding], out: &mut W) -> io::Result<()> {
        let views: Vec<FindingView> = findings.iter().map(Into::into).collect();
        serde_json::to_writer_pretty(&mut *out, &views)?;
        writeln!(out)
    }
}
