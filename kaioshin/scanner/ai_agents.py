"""AI coding agent security benchmark.

Evaluates the security posture of AI coding tools installed on this Mac.
Rating based on: file access control, sandboxing, permission model, MCP isolation.
"""

from dataclasses import dataclass
from pathlib import Path
import subprocess


@dataclass
class AgentRating:
    """Security rating for an AI coding agent."""

    name: str
    installed: bool
    version: str
    stars: int  # 1-5
    strengths: list[str]
    weaknesses: list[str]
    detail: str


# Rating criteria and known agent profiles
AGENT_PROFILES = {
    "Claude Code": {
        "detect": ["claude"],
        "stars": 5,
        "strengths": [
            "Per-file approval — never silently reads files",
            "MCP servers run as isolated local processes",
            "sandbox-exec compatible (Kaioshin v1)",
            "CLAUDE.md permission boundaries",
            "Hook system for pre/post tool validation",
        ],
        "weaknesses": [
            "User can grant broad permissions via allowedTools",
        ],
    },
    "Cursor": {
        "detect": ["cursor"],
        "stars": 2,
        "strengths": [
            "IDE-integrated, visible file access",
        ],
        "weaknesses": [
            "Full workspace directory access without per-file approval",
            "No process isolation or sandboxing",
            "Extensions can access all open files",
        ],
    },
    "GitHub Copilot": {
        "detect": ["copilot"],
        "stars": 3,
        "strengths": [
            "Read-only by default (code completion)",
            "No file write capability in base mode",
        ],
        "weaknesses": [
            "Copilot Chat can suggest file modifications",
            "No sandbox or isolation mechanism",
            "Workspace-level access in VS Code",
        ],
    },
    "Gemini CLI": {
        "detect": ["gemini"],
        "stars": 3,
        "strengths": [
            "File access requires approval",
            "Google's safety filters active",
        ],
        "weaknesses": [
            "No per-file granular control",
            "No sandbox-exec compatibility tested",
            "Newer tool, less battle-tested",
        ],
    },
    "Windsurf": {
        "detect": ["windsurf"],
        "stars": 2,
        "strengths": [
            "IDE-based, visible operations",
        ],
        "weaknesses": [
            "Full workspace access",
            "No per-file approval",
            "No sandboxing",
        ],
    },
    "Devin": {
        "detect": ["devin"],
        "stars": 3,
        "strengths": [
            "Runs in cloud sandbox (not on your machine)",
            "Isolated VM environment",
        ],
        "weaknesses": [
            "Your code is sent to remote servers",
            "Less control over what it accesses in the VM",
        ],
    },
}


def _detect_tool(commands: list[str]) -> tuple[bool, str]:
    """Check if a tool is installed and get its version."""
    for cmd in commands:
        try:
            result = subprocess.run(
                [cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                version = result.stdout.strip().split("\n")[0][:50]
                return True, version
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False, ""


def scan_all() -> list[AgentRating]:
    """Scan for installed AI coding agents and rate their security."""
    ratings = []

    for agent_name, profile in AGENT_PROFILES.items():
        installed, version = _detect_tool(profile["detect"])
        ratings.append(
            AgentRating(
                name=agent_name,
                installed=installed,
                version=version,
                stars=profile["stars"],
                strengths=profile["strengths"],
                weaknesses=profile["weaknesses"],
                detail=f"{'Installed' if installed else 'Not found'}{' — ' + version if version else ''}",
            )
        )

    # Sort: installed first, then by stars descending
    ratings.sort(key=lambda x: (not x.installed, -x.stars))

    return ratings
