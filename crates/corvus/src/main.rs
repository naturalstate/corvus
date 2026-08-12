// ©AngelaMos | 2026
// main.rs

mod cli;
mod live;
mod report;
mod serve;
#[cfg(feature = "tui")]
mod tui;

use anyhow::Result;
use clap::Parser;

use crate::cli::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.init_tracing();
    cli.run()
}
