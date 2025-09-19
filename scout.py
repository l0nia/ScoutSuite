#!/usr/bin/env python3

import sys


def main():
    if sys.version_info < (3, 7):
        sys.stderr.write("ScoutSuite requires Python 3.7 or newer.\n")
        return 1

    # Import inside the version check so Python 2 never parses async code
    from ScoutSuite.__main__ import run_from_cli

    return run_from_cli()


if __name__ == "__main__":
    sys.exit(main())
