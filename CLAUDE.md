# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

Early scaffolding. `main.py` is still the PyCharm sample script, and there are no dependencies, tests, or package layout yet. Treat structural decisions (package name, test runner, dependency manifest) as open, and update this file when they are made.

## Environment

Python 3.14.6 in `.venv`, created and managed by **uv** (`home` points at uv's managed CPython, not pyenv or Homebrew).

- Install packages with `uv pip install <pkg>` — never bare `pip install`.
- `.venv/bin/pip` is a hand-written shell shim that re-routes to `uv pip`. Without it, `pip` falls through to `~/.pyenv/shims/pip` and installs into pyenv's 3.12.3 instead. Re-running `uv venv` recreates the venv and **destroys the shim**; if that happens, recreate it before using `pip` again.
- The README's `uv venv --python 3.14` line is setup-from-scratch instructions, not something to run against the existing venv.

## Git workflow

Work lands on sprint branches (`sprint-1`, …), never directly on `main`. Pull requests to `main` are opened through the GitHub web UI — the `gh` CLI is not used here.