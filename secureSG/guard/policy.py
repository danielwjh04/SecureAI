"""The typed policy IR: a validated on-disk schema compiled to O(1)-lookup form.

Policy is authored as typed YAML (one or more files that merge), validated against
:class:`PolicySchema`, then compiled into :class:`CompiledPolicy` for O(1) lookups.
Both the enforcer (which consults it) and the Warden authoring front-end (which
produces it) depend on this module.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from secureSG.exceptions import PolicyError
from secureSG.guard.taint import TaintTier
from secureSG.schemas.verdict import Verdict


class PolicySchema(BaseModel):
    """Validated on-disk policy; one or more YAML files merge into this shape."""

    model_config = ConfigDict(extra="forbid")

    denylist: list[str] = Field(default_factory=list)
    external_comms_tools: list[str] = Field(default_factory=list)
    taint_sources: dict[str, TaintTier] = Field(default_factory=dict)
    tool_rules: dict[str, Verdict] = Field(default_factory=dict)
    injection_signatures: list[str] = Field(default_factory=list)
    content_scan_sources: list[str] = Field(default_factory=list)

    @field_validator("taint_sources", mode="before")
    @classmethod
    def _tiers_by_name(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        coerced: dict[str, TaintTier] = {}
        for tool, tier in value.items():
            if isinstance(tier, str):
                try:
                    coerced[tool] = TaintTier[tier]
                except KeyError as exc:
                    raise ValueError(f"unknown taint tier: {tier!r}") from exc
            else:
                coerced[tool] = tier
        return coerced


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    """Compiled, O(1)-lookup form of the merged policy."""

    denylist: frozenset[str]
    external_comms_tools: frozenset[str]
    taint_sources: dict[str, TaintTier]
    tool_rules: dict[str, Verdict]
    injection_signatures: frozenset[str]
    content_scan_sources: frozenset[str]

    def is_denied(self, tool: str) -> bool:
        """Whether a tool is unconditionally blocked. O(1)."""
        return tool in self.denylist

    def is_external_comms(self, tool: str) -> bool:
        """Whether a tool is an external-communication sink. O(1)."""
        return tool in self.external_comms_tools

    def is_content_scan_source(self, tool: str) -> bool:
        """Whether a tool's results are untrusted content to scan. O(1)."""
        return tool in self.content_scan_sources

    def taint_tier_for_source(self, tool: str) -> TaintTier | None:
        """The taint tier a tool's output carries, if it is a source. O(1)."""
        return self.taint_sources.get(tool)

    def rule_for(self, tool: str) -> Verdict | None:
        """The affirmative verdict for a tool, if one is defined. O(1)."""
        return self.tool_rules.get(tool)


def load_policy(policy_dir: Path) -> CompiledPolicy:
    """Load and merge every ``*.yaml`` policy file in a directory.

    Raises:
        PolicyError: if any policy file is malformed.

    Time complexity: O(total policy size). Space complexity: O(rule count).
    """
    merged = PolicySchema()
    for path in sorted(policy_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            partial = PolicySchema.model_validate(data)
        except (yaml.YAMLError, ValidationError) as exc:
            raise PolicyError(f"invalid policy file {path.name}: {exc}") from exc
        merged = PolicySchema(
            denylist=[*merged.denylist, *partial.denylist],
            external_comms_tools=[
                *merged.external_comms_tools,
                *partial.external_comms_tools,
            ],
            taint_sources={**merged.taint_sources, **partial.taint_sources},
            tool_rules={**merged.tool_rules, **partial.tool_rules},
            injection_signatures=[
                *merged.injection_signatures,
                *partial.injection_signatures,
            ],
            content_scan_sources=[
                *merged.content_scan_sources,
                *partial.content_scan_sources,
            ],
        )
    return CompiledPolicy(
        denylist=frozenset(merged.denylist),
        external_comms_tools=frozenset(merged.external_comms_tools),
        taint_sources=dict(merged.taint_sources),
        tool_rules=dict(merged.tool_rules),
        injection_signatures=frozenset(merged.injection_signatures),
        content_scan_sources=frozenset(merged.content_scan_sources),
    )
