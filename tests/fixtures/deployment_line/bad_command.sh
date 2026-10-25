#!/usr/bin/env bash
# A shell script that calls a posture command this repository does not ship.
# It exists so the deployment-line gate can be tested against a unit that
# references a script whose own invocations have drifted.
set -euo pipefail
posture not-a-command --db /tmp/x.db
