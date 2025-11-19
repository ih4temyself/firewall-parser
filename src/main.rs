use std::{fs, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json;
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
        #[arg(short, long)]
        json: bool,
        #[arg(short, long, value_name = "OUTPUT")]
        output: Option<PathBuf>,
    },
    Credits,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse { path, json, output } => parse_file(path, json, output)?,
        Commands::Credits => {
            println!("ufw rule parser built with pest, anyhow, and thiserror.");
        }
    }

    Ok(())
}

fn parse_file(path: PathBuf, json: bool, output: Option<PathBuf>) -> Result<()> {
    let contents = fs::read_to_string(&path)?;
    let rules = parse_rules(&contents)?;

    if let Some(output_path) = output {
        if !json {
            return Err(anyhow::anyhow!("--output flag requires --json flag"));
        }
        let json_str = serde_json::to_string_pretty(&rules)?;
        fs::write(&output_path, json_str)?;
        eprintln!("JSON written to: {}", output_path.display());
    } else if json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
    } else {
        println!("{rules:#?}");
    }
    Ok(())
}
