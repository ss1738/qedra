"""Shared policy loading for the hook, MCP server, and attestation CLI."""
import os

from .guardrail import DEFAULT_SPEC, PolicySpec
from .presets import preset_spec


def load_policy_spec(path: str | None = None, presets: str = "") -> PolicySpec:
    spec = DEFAULT_SPEC
    if path:
        with open(path) as source:
            spec = PolicySpec.from_json(source.read())
    names = [name.strip() for name in presets.split(",") if name.strip()]
    return preset_spec(*names, base=spec) if names else spec


def policy_from_environment() -> PolicySpec:
    return load_policy_spec(os.environ.get("GUARDRAIL_POLICY_SPEC"),
                            os.environ.get("GUARDRAIL_PRESET", ""))
