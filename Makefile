.PHONY: prove prove-verbose clean verify help

# Default: run full conformance proof
prove:
	@python prove.py

# Verbose: show canonical forms and frozen hashes
prove-verbose:
	@python prove.py --verbose

# Run a single vector (usage: make vector ID=V5a)
vector:
	@python prove.py --vector $(ID)

# Quick run without signing
quick:
	@python prove.py --no-sign

# Clean evidence artifacts
clean:
	@rm -rf evidence/
	@echo "Evidence directory cleaned."

# Help
help:
	@echo "Targets:"
	@echo "  prove          Run full conformance proof with receipts"
	@echo "  prove-verbose  Run with CF/FH details"
	@echo "  vector ID=V1a  Run a single vector"
	@echo "  quick          Run without receipt signing"
	@echo "  clean          Remove evidence directory"
