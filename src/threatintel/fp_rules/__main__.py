"""`python -m threatintel.fp_rules` entry point.

Kept separate from `engine.py` so executing the CLI does not import the module under a
different name than the package already did, which would emit a runpy warning.
"""

from threatintel.fp_rules.engine import main

raise SystemExit(main())
