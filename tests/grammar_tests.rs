use anyhow::{Result, anyhow};
use pest::Parser;
use ufw_rule_parser::{FirewallGrammar, Rule};

#[test]
fn action_parses_valid_values() -> Result<()> {
    let actions = ["allow", "deny", "reject", "limit"];

    for text in actions {
        let mut pairs = FirewallGrammar::parse(Rule::action, text)?;
        let pair = pairs.next().ok_or_else(|| anyhow!("no pair for action"))?;
        assert_eq!(pair.as_str(), text);
    }

    let err = FirewallGrammar::parse(Rule::action, "block");
    assert!(err.is_err());

    Ok(())
}

#[test]
fn direction_parses_in_and_out() -> Result<()> {
    let mut in_pairs = FirewallGrammar::parse(Rule::direction, "in")?;
    assert_eq!(in_pairs.next().unwrap().as_str(), "in");

    let mut out_pairs = FirewallGrammar::parse(Rule::direction, "out")?;
    assert_eq!(out_pairs.next().unwrap().as_str(), "out");

    let err = FirewallGrammar::parse(Rule::direction, "both");
    assert!(err.is_err());

    Ok(())
}

#[test]
fn addr_parses_keywords_and_ips() -> Result<()> {
    let mut any_pairs = FirewallGrammar::parse(Rule::addr, "any")?;
    assert_eq!(any_pairs.next().unwrap().as_str(), "any");

    let mut internal_pairs = FirewallGrammar::parse(Rule::addr, "internal")?;
    assert_eq!(internal_pairs.next().unwrap().as_str(), "internal");

    let mut external_pairs = FirewallGrammar::parse(Rule::addr, "external")?;
    assert_eq!(external_pairs.next().unwrap().as_str(), "external");

    let mut ip_pairs = FirewallGrammar::parse(Rule::addr, "10.0.0.1")?;
    assert_eq!(ip_pairs.next().unwrap().as_str(), "10.0.0.1");

    let mut cidr_pairs = FirewallGrammar::parse(Rule::addr, "10.0.0.0/24")?;
    assert_eq!(cidr_pairs.next().unwrap().as_str(), "10.0.0.0/24");

    Ok(())
}

#[test]
fn port_clause_parses_number() -> Result<()> {
    let mut pairs = FirewallGrammar::parse(Rule::port_clause, "port 22")?;
    let pair = pairs.next().ok_or_else(|| anyhow!("no pair"))?;
    assert_eq!(pair.as_str(), "port 22");

    let err = FirewallGrammar::parse(Rule::port_clause, "port x");
    assert!(err.is_err());

    Ok(())
}

#[test]
fn port_number_accepts_digits_only() -> Result<()> {
    let mut ok = FirewallGrammar::parse(Rule::port_number, "65535")?;
    assert_eq!(ok.next().unwrap().as_str(), "65535");
    Ok(())
}

#[test]
fn proto_clause_parses_values() -> Result<()> {
    for text in ["proto tcp", "proto udp", "proto any"] {
        let mut pairs = FirewallGrammar::parse(Rule::proto_clause, text)?;
        let pair = pairs.next().ok_or_else(|| anyhow!("no pair"))?;
        assert_eq!(pair.as_str(), text);
    }

    let err = FirewallGrammar::parse(Rule::proto_clause, "proto icmp");
    assert!(err.is_err());

    Ok(())
}

#[test]
fn service_rule_parses_basic_service() -> Result<()> {
    let input = "allow ssh";
    let mut pairs = FirewallGrammar::parse(Rule::service_rule, input)?;
    let pair = pairs.next().ok_or_else(|| anyhow!("no pair"))?;
    assert_eq!(pair.as_str(), input);
    Ok(())
}

#[test]
fn addr_rule_parses_complex_syntax() -> Result<()> {
    let input = "allow in from internal to external port 443 proto tcp";
    let mut pairs = FirewallGrammar::parse(Rule::addr_rule, input)?;
    let pair = pairs.next().ok_or_else(|| anyhow!("no pair"))?;
    assert_eq!(pair.as_str(), input);
    Ok(())
}

#[test]
fn file_parses_multiple_lines_with_comments() -> Result<()> {
    let input = r#"
# incoming HTTPS from internal to external
allow in from internal to external port 443 proto tcp  # https

# DNS queries to external resolvrerr
deny out to 8.8.8.8 port 53 proto udp
allow ssh
"#;

    let mut pairs = FirewallGrammar::parse(Rule::file, input)?;
    let pair = pairs.next().ok_or_else(|| anyhow!("no pair"))?;
    assert_eq!(pair.as_rule(), Rule::file);

    Ok(())
}

#[test]
fn ident_parses_letters_numbers_and_dashes() -> Result<()> {
    let mut pair = FirewallGrammar::parse(Rule::ident, "ssh-service1")?;
    assert_eq!(pair.next().unwrap().as_str(), "ssh-service1");
    Ok(())
}

#[test]
fn ip_parses_ipv4_and_cidr() -> Result<()> {
    let mut ipv4 = FirewallGrammar::parse(Rule::ip, "192.168.0.1")?;
    assert_eq!(ipv4.next().unwrap().as_str(), "192.168.0.1");

    let mut cidr = FirewallGrammar::parse(Rule::ip, "192.168.0.0/24")?;
    assert_eq!(cidr.next().unwrap().as_str(), "192.168.0.0/24");
    Ok(())
}

#[test]
fn interface_clause_parses_identifier() -> Result<()> {
    let mut pairs = FirewallGrammar::parse(Rule::interface_clause, "on eth0")?;
    assert_eq!(pairs.next().unwrap().as_str(), "on eth0");
    Ok(())
}

#[test]
fn from_clause_requires_address() -> Result<()> {
    let mut pairs = FirewallGrammar::parse(Rule::from_clause, "from internal")?;
    assert_eq!(pairs.next().unwrap().as_str(), "from internal");

    let err = FirewallGrammar::parse(Rule::from_clause, "from");
    assert!(err.is_err());
    Ok(())
}

#[test]
fn to_clause_accepts_keywords() -> Result<()> {
    let mut pairs = FirewallGrammar::parse(Rule::to_clause, "to any")?;
    assert_eq!(pairs.next().unwrap().as_str(), "to any");
    Ok(())
}

#[test]
fn comment_rule_tracks_text_until_newline() -> Result<()> {
    FirewallGrammar::parse(Rule::COMMENT, "# allow https traffic")?;
    Ok(())
}

#[test]
fn line_rule_handles_rule_and_comment_only_lines() -> Result<()> {
    FirewallGrammar::parse(Rule::line, "allow ssh # fast path")?;
    FirewallGrammar::parse(Rule::line, "# full comment line")?;
    Ok(())
}
