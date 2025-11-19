# ufw-rule-parser

ufw-rule-parser is a parser for a small ufw-like firewall rule language.  
it uses the pest parsing library and a custom grammar defined in grammar.pest.  
it supports address-based rules, service-based rules, and special address keywords such as internal and external.

## crates.io link
https://crates.io/crates/ufw-rule-parser

## example rules

```
allow ssh
allow in on eth0 from internal to external port 443 proto tcp
deny out to 8.8.8.8 port 53 proto udp
```

## cli usage

parse a rules file and print the structured output:

```bash
cargo run -- parse examples/sample.rules
```

output as json format:

```bash
cargo run -- parse examples/sample.rules --json
```

write json output to a file:

```bash
cargo run -- parse examples/sample.rules --json --output rules.json
```

short form for output flag:

```bash
cargo run -- parse examples/sample.rules --json -o rules.json
```

show help:

```bash
cargo run -- --help
cargo run -- parse --help
```

show credits:

```bash
cargo run -- credits
```

## output formats

the parser supports two output formats:

- **debug format (default)**: pretty-printed rust structs showing the parsed rules.
- **json format**: structured json output with typed fields. use `--json` flag to enable.

when using `--output` or `-o` flag, json is written to the specified file instead of stdout.  
the `--output` flag requires the `--json` flag to be set.

## project structure

- `src/grammar.pest` defines the grammar used by the parser  
- `src/lib.rs` exposes the parser api and typed ast structures  
- `src/main.rs` implements the cli interface  
- `tests/grammar_tests.rs` contains unit tests for each grammar rule  
- `tests/parser_tests.rs` contains integration tests for ast parsing  
- `examples/` contains sample rule files for testing

## grammar overview

### grammar diagram

```
file
  └── line* (zero or more lines)
      ├── service_rule
      │   └── action + ident
      ├── addr_rule
      │   ├── action (required)
      │   ├── direction? (optional)
      │   ├── interface_clause? (optional)
      │   └── (from_clause | to_clause | port_clause | proto_clause)+ (one or more)
      └── COMMENT? (optional comment)
```

### grammar rules

the grammar in `grammar.pest` defines rules using pest syntax:

- `action`: matches `allow`, `deny`, `reject`, or `limit`
- `direction`: matches `in` or `out`
- `ident`: matches identifiers with letters, numbers, underscores, and dashes
- `ip`: matches ip addresses and cidr notation
- `addr`: matches `any`, `internal`, `external`, or ip addresses
- `port_clause`: matches `port` followed by a number
- `proto_clause`: matches `proto` followed by `tcp`, `udp`, or `any`
- `interface_clause`: matches `on` followed by an identifier
- `from_clause` and `to_clause`: match `from` or `to` followed by an address
- `addr_rule`: combines action, optional direction, optional interface, and one or more clauses
- `service_rule`: matches action followed by an identifier
- `line`: matches a rule with optional comment, or just a comment
- `file`: matches multiple lines from start to end of input

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
the library converts these pairs into typed rust structures (firewallrule, servicerule, addressrule).  
integration tests verify that the grammar accepts valid rules and rejects invalid ones.

## testing

run all tests:

```bash
cargo test
```

format code:

```bash
cargo fmt
```

lint code:

```bash
cargo clippy --all-features --all-targets -- -D warnings
```

use the makefile for common tasks:

```bash
make test
make fmt
make clippy
make run
```
