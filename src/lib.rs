use pest::{Parser, iterators::Pair};
use pest_derive::Parser;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// pest parser generated from grammar.pest.
#[derive(Parser)]
#[grammar = "./grammar.pest"]
pub struct FirewallGrammar;

/// parsed firewall rule: service or address rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum FirewallRule {
    /// service rule (e.g., allow ssh)
    Service(ServiceRule),
    /// address rule with optional direction, interface, from/to, port, proto
    Address(AddressRule),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRule {
    pub action: Action,
    pub service: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRule {
    pub action: Action,
    pub direction: Option<Direction>,
    pub interface: Option<String>,
    pub from: Option<Address>,
    pub to: Option<Address>,
    pub port: Option<u16>,
    pub proto: Option<Protocol>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Reject,
    Limit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum Address {
    Any,
    Internal,
    External,
    IpCidr(String),
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("pest parse error: {0}")]
    Pest(Box<pest::error::Error<Rule>>),
    #[error("{0}")]
    Message(String),
}

type ParseResult<T> = Result<T, ParseError>;

impl From<pest::error::Error<Rule>> for ParseError {
    fn from(value: pest::error::Error<Rule>) -> Self {
        Self::Pest(Box::new(value))
    }
}

/// parses firewall rules file into vector of rules.
pub fn parse_rules(input: &str) -> ParseResult<Vec<FirewallRule>> {
    let mut file_pairs = FirewallGrammar::parse(Rule::file, input)?;
    let file_pair = file_pairs
        .next()
        .ok_or_else(|| ParseError::Message("expected file pair to be present".into()))?;

    let mut rules = Vec::new();
    for pair in file_pair.into_inner() {
        match pair.as_rule() {
            Rule::service_rule => {
                rules.push(FirewallRule::Service(parse_service_rule(pair)?));
            }
            Rule::addr_rule => {
                rules.push(FirewallRule::Address(parse_address_rule(pair)?));
            }
            Rule::line | Rule::NEWLINE | Rule::COMMENT | Rule::EOI => {}
            unexpected => {
                return Err(ParseError::Message(format!(
                    "unexpected rule inside file: {unexpected:?}"
                )));
            }
        }
    }

    Ok(rules)
}

fn parse_service_rule(pair: Pair<Rule>) -> ParseResult<ServiceRule> {
    let mut inner = pair.into_inner();
    let action_pair = inner
        .next()
        .ok_or_else(|| ParseError::Message("service rule missing action".into()))?;
    let ident_pair = inner
        .next()
        .ok_or_else(|| ParseError::Message("service rule missing identifier".into()))?;

    Ok(ServiceRule {
        action: parse_action(action_pair.as_str())?,
        service: ident_pair.as_str().to_string(),
    })
}

fn parse_address_rule(pair: Pair<Rule>) -> ParseResult<AddressRule> {
    let mut inner = pair.into_inner();
    let action_pair = inner
        .next()
        .ok_or_else(|| ParseError::Message("address rule missing action".into()))?;
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
                let ident = sub_pair.into_inner().next().ok_or_else(|| {
                    ParseError::Message("interface clause missing identifier".into())
                })?;
                rule.interface = Some(ident.as_str().to_string());
            }
            Rule::from_clause => {
                let addr_pair = sub_pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| ParseError::Message("from clause missing address".into()))?;
                rule.from = Some(parse_address(addr_pair)?);
            }
            Rule::to_clause => {
                let addr_pair = sub_pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| ParseError::Message("to clause missing address".into()))?;
                rule.to = Some(parse_address(addr_pair)?);
            }
            Rule::port_clause => {
                let port_pair = sub_pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| ParseError::Message("port clause missing number".into()))?;
                rule.port = Some(parse_port(port_pair.as_str())?);
            }
            Rule::proto_clause => {
                let proto_pair = sub_pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| ParseError::Message("proto clause missing proto".into()))?;
                rule.proto = Some(parse_protocol(proto_pair.as_str())?);
            }
            other => {
                return Err(ParseError::Message(format!(
                    "unexpected rule inside addr_rule: {other:?}"
                )));
            }
        }
    }

    Ok(rule)
}

fn parse_action(text: &str) -> ParseResult<Action> {
    match text {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        "reject" => Ok(Action::Reject),
        "limit" => Ok(Action::Limit),
        other => Err(ParseError::Message(format!("invalid action: {other}"))),
    }
}

fn parse_direction(text: &str) -> ParseResult<Direction> {
    match text {
        "in" => Ok(Direction::In),
        "out" => Ok(Direction::Out),
        other => Err(ParseError::Message(format!("invalid direction: {other}"))),
    }
}

fn parse_protocol(text: &str) -> ParseResult<Protocol> {
    match text {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "any" => Ok(Protocol::Any),
        other => Err(ParseError::Message(format!("invalid protocol: {other}"))),
    }
}

fn parse_address(pair: Pair<Rule>) -> ParseResult<Address> {
    let text = pair.as_str();
    match text {
        "any" => Ok(Address::Any),
        "internal" => Ok(Address::Internal),
        "external" => Ok(Address::External),
        _ => Ok(Address::IpCidr(text.to_string())),
    }
}

fn parse_port(text: &str) -> ParseResult<u16> {
    text.parse::<u16>()
        .map_err(|_| ParseError::Message(format!("invalid port value: {text}")))
}

/// grammar rule documentation from grammar.pest.
pub mod grammar_docs {
    /// matches spaces and tabs (silent rule).
    pub const WHITESPACE: &str = r#"WHITESPACE = _{ " " | "\t" }"#;
    /// matches line breaks (silent rule).
    pub const NEWLINE: &str = r#"NEWLINE = _{ "\r\n" | "\n" }"#;
    pub const COMMENT: &str = r##"COMMENT = _{ "#" ~ (!NEWLINE ~ ANY)* }"##;
    pub const ACTION: &str = r#"action = { "allow" | "deny" | "reject" | "limit" }"#;
    /// matches direction: in or out.
    pub const DIRECTION: &str = r#"direction = { "in" | "out" }"#;
    pub const IDENT: &str = r#"ident = @{ (ASCII_ALPHANUMERIC | "_" | "-")+ }"#;
    /// matches ip address or cidr notation.
    pub const IP: &str = r#"ip = @{ (ASCII_DIGIT | "." | "/")+ }"#;
    /// matches address: any, internal, external, or ip.
    pub const ADDR: &str = r#"addr = { "any" | "internal" | "external" | ip }"#;
    /// matches port number as digits.
    pub const PORT_NUMBER: &str = r#"port_number = @{ ASCII_DIGIT+ }"#;
    pub const PORT_CLAUSE: &str = r#"port_clause = { "port" ~ port_number }"#;
    /// matches protocol: tcp, udp, or any.
    pub const PROTO: &str = r#"proto = { "tcp" | "udp" | "any" }"#;
    pub const PROTO_CLAUSE: &str = r#"proto_clause = { "proto" ~ proto }"#;
    pub const INTERFACE_CLAUSE: &str = r#"interface_clause = { "on" ~ ident }"#;
    /// matches "from" keyword followed by address.
    pub const FROM_CLAUSE: &str = r#"from_clause = { "from" ~ addr }"#;
    pub const TO_CLAUSE: &str = r#"to_clause = { "to" ~ addr }"#;
    /// matches address rule: action, optional direction/interface, one or more clauses.
    pub const ADDR_RULE: &str = r#"addr_rule = { action ~ direction? ~ interface_clause? ~ (from_clause | to_clause | port_clause | proto_clause)+ }"#;
    pub const SERVICE_RULE: &str = r#"service_rule = { action ~ ident }"#;
    pub const LINE: &str = r#"line = _{ (addr_rule | service_rule) ~ COMMENT? | COMMENT }"#;
    pub const FILE: &str = r#"file = { SOI ~ (line? ~ NEWLINE)* ~ EOI }"#;
}
