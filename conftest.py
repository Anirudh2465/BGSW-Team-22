import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

# Ensure monorepo root is first in sys.path
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Remove external non-monorepo interfering paths
sys.path = [p for p in sys.path if "routing-service" not in p]
