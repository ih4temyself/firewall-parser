use anyhow::Result;

use firewall_parser::{
    parse_rules, Action, Address, AddressRule, Direction, FirewallRule, Protocol, ServiceRule,
};

#[test]
fn parses_file_into_structured_rules() -> Result<()> {
    let input = r#"
# comment before service rule
allow ssh

# address rule with all optional fields
allow in on eth0 from internal to external port 443 proto tcp

# minimal addr rule
deny out to 8.8.8.8 port 53 proto udp
"#;

    let rules = parse_rules(input)?;

    assert_eq!(
        rules,
        vec![
            FirewallRule::Service(ServiceRule {
                action: Action::Allow,
                service: "ssh".into(),
            }),
            FirewallRule::Address(AddressRule {
                action: Action::Allow,
                direction: Some(Direction::In),
                interface: Some("eth0".into()),
                from: Some(Address::Internal),
                to: Some(Address::External),
                port: Some(443),
                proto: Some(Protocol::Tcp),
            }),
            FirewallRule::Address(AddressRule {
                action: Action::Deny,
                direction: Some(Direction::Out),
                interface: None,
                from: None,
                to: Some(Address::IpCidr("8.8.8.8".into())),
                port: Some(53),
                proto: Some(Protocol::Udp),
            }),
        ]
    );

    Ok(())
}

