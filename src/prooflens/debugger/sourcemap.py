"""Circom source code mapping and line highlighter.

Parses Circom source files, extracts templates and signal declarations, and maps
R1CS constraints and failing signals directly to the corresponding lines of code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union


@dataclass
class SourceLocation:
    """A specific line or block in a Circom source file."""

    file_path: str
    line_number: int
    line_text: str
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)


class CircomSourceMapper:
    """Extracts signal declarations, constraints, and source locations from Circom files."""

    def __init__(self) -> None:
        self.sources: Dict[str, List[str]] = {}
        # Signal name -> (file_path, line_number)
        self.signal_declarations: Dict[str, Tuple[str, int]] = {}
        # Template name -> (file_path, start_line, end_line)
        self.templates: Dict[str, Tuple[str, int, int]] = {}

    def load_source_file(self, path: Union[str, Path]) -> None:
        """Load and index a Circom file."""
        p = Path(path)
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        self.sources[p.name] = lines
        self._index_file(p.name, lines)

    def load_source_text(self, filename: str, content: str) -> None:
        """Load and index Circom source text."""
        lines = content.splitlines(keepends=True)
        self.sources[filename] = lines
        self._index_file(filename, lines)

    def _index_file(self, filename: str, lines: List[str]) -> None:
        """Index templates and signal declarations."""
        template_pattern = re.compile(r"template\s+([A-Za-z0-9_]+)\s*\(")
        signal_pattern = re.compile(r"signal\s+(input|output)?\s*([A-Za-z0-9_]+)")

        curr_template: Optional[str] = None
        curr_template_start = 1

        for idx, line in enumerate(lines, start=1):
            t_match = template_pattern.search(line)
            if t_match:
                curr_template = t_match.group(1)
                curr_template_start = idx

            s_match = signal_pattern.search(line)
            if s_match:
                sig_name = s_match.group(2)
                # Store local signal name
                self.signal_declarations[sig_name] = (filename, idx)
                if curr_template:
                    self.signal_declarations[f"{curr_template}.{sig_name}"] = (filename, idx)

    def get_signal_location(self, symbol_path: str) -> Optional[SourceLocation]:
        """Find the declaration line for a symbol path (e.g. 'main.multiplier.out')."""
        # Try exact or leaf match
        parts = symbol_path.split(".")
        candidates = [symbol_path, parts[-1]]
        if len(parts) >= 2:
            candidates.append(f"{parts[-2]}.{parts[-1]}")

        for cand in candidates:
            if cand in self.signal_declarations:
                fname, line_no = self.signal_declarations[cand]
                return self.get_location(fname, line_no)

        return None

    def get_location(self, filename: str, line_number: int, context_lines: int = 2) -> Optional[SourceLocation]:
        """Get source line with surrounding context lines."""
        if filename not in self.sources:
            return None
        lines = self.sources[filename]
        if line_number < 1 or line_number > len(lines):
            return None

        line_idx = line_number - 1
        line_text = lines[line_idx].rstrip()

        start_ctx = max(0, line_idx - context_lines)
        end_ctx = min(len(lines), line_idx + context_lines + 1)

        ctx_before = [l.rstrip() for l in lines[start_ctx:line_idx]]
        ctx_after = [l.rstrip() for l in lines[line_idx + 1:end_ctx]]

        return SourceLocation(
            file_path=filename,
            line_number=line_number,
            line_text=line_text,
            context_before=ctx_before,
            context_after=ctx_after,
        )
