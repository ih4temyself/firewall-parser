use anyhow::{anyhow, bail, Result};
use pest::{iterators::Pair, Parser};
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "./grammar.pest"]
pub struct FirewallGrammar;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallRule {
    Service(ServiceRule),
    Address(AddressRule),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRule {
    pub action: Action,
    pub service: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRule {
    pub action: Action,
    pub direction: Option<Direction>,
    pub interface: Option<String>,
    pub from: Option<Address>,
    pub to: Option<Address>,
    pub port: Option<u16>,
    pub proto: Option<Protocol>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
    Reject,
    Limit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Any,
    Internal,
    External,
    IpCidr(String),
}

pub fn parse_rules(input: &str) -> Result<Vec<FirewallRule>> {
    let mut file_pairs = FirewallGrammar::parse(Rule::file, input)?;
    let file_pair = file_pairs
        .next()
        .ok_or_else(|| anyhow!("expected file pair to be present"))?;

    let mut rules = Vec::new();
    for pair in file_pair.into_inner() {
        match pair.as_rule() {
            Rule::service_rule => {
                rules.push(FirewallRule::Service(parse_service_rule(pair)?));
            }
            Rule::addr_rule => {
                rules.push(FirewallRule::Address(parse_address_rule(pair)?));
            }
            Rule::EOI => {}
            _ => {}
        }
    }

    Ok(rules)
}

fn parse_service_rule(pair: Pair<Rule>) -> Result<ServiceRule> {
    let mut inner = pair.into_inner();
    let action_pair = inner.next().ok_or_else(|| anyhow!("service rule missing action"))?;
    let ident_pair = inner
        .next()
        .ok_or_else(|| anyhow!("service rule missing identifier"))?;

    Ok(ServiceRule {
        action: parse_action(action_pair.as_str())?,
        service: ident_pair.as_str().to_string(),
    })
}

fn parse_address_rule(pair: Pair<Rule>) -> Result<AddressRule> {
    let mut inner = pair.into_inner();
    let action_pair = inner
        .next()
        .ok_or_else(|| anyhow!("address rule missing action"))?;
    let action = parse_action(action_pair.as_str())?;

    let mut rule = AddressRule {
        action,
        direction: None,
        interface: None,
        from: None,
        to: None,
        port: None,
        proto: None,
    };

    for sub_pair in inner {
        match sub_pair.as_rule() {
            Rule::direction => {
                rule.direction = Some(parse_direction(sub_pair.as_str())?);
            }
            Rule::interface_clause => {
                let ident = sub_pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| anyhow!("interface clause missing identifier"))?;
                rule.interface = Some(ident.as_str().to_string());
            }
            Rule::from_clause => {
                let addr_pair = sub_pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| anyhow!("from clause missing address"))?;
                rule.from = Some(parse_address(addr_pair)?);
            }
            Rule::to_clause => {
                let addr_pair = sub_pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| anyhow!("to clause missing address"))?;
                rule.to = Some(parse_address(addr_pair)?);
            }
            Rule::port_clause => {
                let port_pair = sub_pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| anyhow!("port clause missing number"))?;
                rule.port = Some(parse_port(port_pair.as_str())?);
            }
            Rule::proto_clause => {
                let proto_pair = sub_pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| anyhow!("proto clause missing proto"))?;
                rule.proto = Some(parse_protocol(proto_pair.as_str())?);
            }
            other => {
                bail!("unexpected rule inside addr_rule: {other:?}");
            }
        }
    }

    Ok(rule)
}

fn parse_action(text: &str) -> Result<Action> {
    match text {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        "reject" => Ok(Action::Reject),
        "limit" => Ok(Action::Limit),
        other => bail!("invalid action: {other}"),
    }
}

fn parse_direction(text: &str) -> Result<Direction> {
    match text {
        "in" => Ok(Direction::In),
        "out" => Ok(Direction::Out),
        other => bail!("invalid direction: {other}"),
    }
}

fn parse_protocol(text: &str) -> Result<Protocol> {
    match text {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "any" => Ok(Protocol::Any),
        other => bail!("invalid protocol: {other}"),
    }
}

fn parse_address(pair: Pair<Rule>) -> Result<Address> {
    let text = pair.as_str();
    match text {
        "any" => Ok(Address::Any),
        "internal" => Ok(Address::Internal),
        "external" => Ok(Address::External),
        _ => Ok(Address::IpCidr(text.to_string())),
    }
}

fn parse_port(text: &str) -> Result<u16> {
    text.parse::<u16>()
        .map_err(|_| anyhow!("invalid port value: {text}"))
}
