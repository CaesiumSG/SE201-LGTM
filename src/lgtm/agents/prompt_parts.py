"""Tool guidance shared by the review agents' prompts."""

from __future__ import annotations

import re
from dataclasses import dataclass

from lgtm.agents import registry
from lgtm.agents.base import SNAPSHOT_LABELS

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")


@dataclass(frozen=True)
class ToolGuidance:
    tool_names: tuple[str, ...]
    graph_tools: bool
    snapshot_labels: tuple[str, ...]
    max_tool_calls: int


def tool_guidance(toolbox, graph: bool = True) -> ToolGuidance:
    names = tuple(tool.name for tool in toolbox.build_tools(graph=graph))
    return ToolGuidance(
        tool_names=names,
        graph_tools=any(name.startswith("investigate_") for name in names),
        snapshot_labels=SNAPSHOT_LABELS if getattr(toolbox, "shas", None) is not None else ("base",),
        max_tool_calls=toolbox.budget,
    )


def render_tool_section(guidance: ToolGuidance) -> str:
    tool_lines = registry.entry("tools.guidance")
    lines = [
        registry.entry("shared.tool_section_intro"),
        *(f"- {tool_lines.get(name, name)}" for name in guidance.tool_names),
    ]
    if "pr" in guidance.snapshot_labels:
        lines += ["", registry.entry("shared.snapshot_argument")]
    else:
        lines += ["", registry.entry("shared.snapshot_argument_base_only")]
    lines += ["", registry.entry("shared.tool_output_notice")]
    if guidance.graph_tools:
        graph_names = " and ".join(n for n in guidance.tool_names if n.startswith("investigate_"))
        lines += ["", registry.render("shared.graph_guidance", graph_names=graph_names)]
    return "\n".join(lines)


def escape_control(text: str) -> str:
    return _CONTROL_CHARS.sub(lambda m: m.group(0).encode("unicode_escape").decode("ascii"), text)


def code_fence(body: str, info: str) -> str:
    # The closing fence must be longer than any backtick run in the body, or content can end the block.
    longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
    marker = "`" * max(3, longest + 1)
    separator = "\n" if body and not body.endswith("\n") else ""
    return f"{marker}{info}\n{body}{separator}{marker}\n"


def untrusted_block(body: str, label: str) -> str:
    return f"{label}\n{code_fence(body, 'text')}"
