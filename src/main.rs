use anyhow::Result;
use firewall_parser::parse_rules;

fn main() -> Result<()> {
    let inp = r#"
	allow ssh
	allow in from internal to external port 443 proto tcp
	deny out to 8.8.8.8 port 53 proto udp
	"#;

    let rules = parse_rules(inp)?;
    println!("{rules:#?}");

    Ok(())
}
