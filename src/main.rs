use std::{fs, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use ufw_rule_parser::parse_rules;

#[derive(Parser)]
#[command(
    name = "ufw rule parser",
    version,
    about = "cli for parsing ufw-style firewall rules into a typed ast."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Parse {
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },
    Credits,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse { path } => parse_file(path)?,
        Commands::Credits => {
            println!("ufw rule parser built with pest, anyhow, and thiserror.");
        }
    }

    Ok(())
}

fn parse_file(path: PathBuf) -> Result<()> {
    let contents = fs::read_to_string(&path)?;
    let rules = parse_rules(&contents)?;
    println!("{rules:#?}");
    Ok(())
}
