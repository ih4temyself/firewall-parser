SHELL := /bin/bash
CARGO := cargo

.PHONY: run help credits test fmt fmt-check clippy check publish clean

run:
	$(CARGO) run -- parse examples/sample.rules

help:
	$(CARGO) run -- help

credits:
	$(CARGO) run -- credits

test:
	$(CARGO) test

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt -- --check

clippy:
	$(CARGO) clippy --all-features --all-targets -- -D warnings

check: fmt-check clippy test

publish: check
	$(CARGO) publish

clean:
	$(CARGO) clean

