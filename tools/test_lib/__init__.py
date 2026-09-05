"""Functional-test catalog for ESP32 Tailscale Gateway.

Each module under this package exposes:
    MODULE_ID  = "<short-name>"
    MODULE_DESC = "<one-line summary>"
    def run(ctx) -> list[Result]

Modules are wired into tools/run_tests.py; see docs/TESTING.md.
"""
