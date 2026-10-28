# posture — canonical verification entry point.
#
# `make verify` is the standing readiness signal for this repository and the
# command the repository policy declares. It runs the full canonical path:
# the test suite, the spine size guard, and the deployment-line command gate.

PYTHON ?= python

.PHONY: verify test verify-all

verify:
	./scripts/verify-all

test:
	$(PYTHON) -m pytest -q

verify-all: verify
