"""Use before other project imports; never byte-compile outside the workspace."""
import sys
sys.dont_write_bytecode = True
from src.io_utils import configure_runtime
configure_runtime()
