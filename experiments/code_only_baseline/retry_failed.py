#!/usr/bin/env python3
"""Resume only missing or error results; preserve successful binary predictions."""
from run_baseline import main

if __name__ == "__main__":
    main(retry_default=True)
