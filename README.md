# ufw-firewall-parser

ufw-firewall-parser is a parser for a small ufw-like firewall rule language.  
it uses the pest parsing library and a custom grammar defined in grammar.pest.
it supports address-based rules, service-based rules, and special address keywords such as internal and external.

## example rules
allow ssh
allow in on eth0 from internal to external port 443 proto tcp
deny out to 8.8.8.8 port 53 proto udp

## project structure

- `src/grammar.pest` defines the grammar used by the parser  
- `src/lib.rs` exposes the generated pest parser  
- `tests/` contains integration tests that check each grammar rule  
- `src/main.rs` shows a basic example of parsing

## grammar overview

the grammar supports:
- actions: `allow`, `deny`, `reject`, `limit`  
- directions: `in`, `out`  
- interfaces: `on eth0`  
- addresses: `any`, `internal`, `external`, or ip/cidr  
- service rules such as `allow ssh`  
- address-based rules combining direction, from/to, ports, and protocol

## parsing process

the parser reads input text and matches it against the grammar rules.  
pest produces a structured tree of pairs that describe which rule matched each part of the input.  
integration tests verify that the grammar accepts valid rules and rejects invalid ones.
