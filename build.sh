#!/bin/sh

mkdocs build
python scripts/build_writeups.py
mkdocs serve