use anyhow::Result;
use pest::Parser;
use firewall_parser::{FirewallGrammar, Rule};

fn main() -> Result<()> {
    let inp = r#"
	allow ssh
	allow in from internal to external port 443 proto tcp
	deny out to 8.8.8.8 port 53 proto udp
	"#;

    let pairs = FirewallGrammar::parse(Rule::file, inp)?;
    println!("{:#?}", pairs);

    Ok(())
}
