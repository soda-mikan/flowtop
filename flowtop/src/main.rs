mod aggregate;
mod app;
mod cli;
mod collector;
mod config;
mod error;
mod filter;
mod record;
mod tui;

use anyhow::Result;
use clap::Parser;

use crate::{cli::Cli, collector::build_collector, config::Config, record::open_recorder};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::try_from(Cli::parse())?;
    let (mut collector, capabilities) = build_collector(&config).await?;
    let recorder = open_recorder(&config)?;
    let result = app::run(config, collector.as_mut(), capabilities, recorder).await;
    let shutdown = collector.shutdown().await;
    result.and(shutdown)
}
