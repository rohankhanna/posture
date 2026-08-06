"""Allow `python -m posture` to run the CLI."""
from .cli import main

raise SystemExit(main())