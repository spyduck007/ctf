#!/bin/sh

python scripts/build_writeups.py
mkdocs build
mkdocs serve
