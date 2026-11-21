"""Allow ``python -m raven``."""

import sys

from raven.cli import main

sys.exit(main())
