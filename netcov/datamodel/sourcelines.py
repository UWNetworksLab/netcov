#   Copyright 2022 Xieyang Xu
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from __future__ import annotations # type hint in the enclosing class
from collections import defaultdict
from typing import Any, DefaultDict, Dict, Set, List
from pybatfish.datamodel.primitives import FileLines

class SourceLines:
    def __init__(self) -> None:
        self.files2lines: DefaultDict[str, Set[int]] = defaultdict(set)
        
    def add_source_lines(self, fileLines: FileLines):
        for line in fileLines.lines:
            self.files2lines[fileLines.filename].add(line)

    def add_line(self, filename: str, line: int) -> None:
        self.files2lines[filename].add(line)

    def intersect(self, other: SourceLines) -> SourceLines:
        res = SourceLines()
        for filename in self.files2lines.keys():
            if filename in other.files2lines:
                for line in self.files2lines[filename]:
                    if line in other.files2lines[filename]:
                        res.add_line(filename, line)
        return res

    def update(self, other: SourceLines) -> None:
        for filename, lines in other.files2lines.items():
            for line in lines:
                self.files2lines[filename].add(line)

    def diff(self, other: SourceLines) -> SourceLines:
        """a.diff(b) = elements in a but not in b
        """
        res = SourceLines()
        for filename in self.files2lines.keys():
            if filename in other.files2lines:
                for line in self.files2lines[filename]:
                    if line not in other.files2lines[filename]:
                        res.add_line(filename, line)
            else:
                for line in self.files2lines[filename]:
                    res.add_line(filename, line)
        return res
    
    def contains(self, fileLines: FileLines) -> bool:
        all_contained = True
        for line in fileLines.lines:
            if line not in self.files2lines[fileLines.filename]:
                all_contained = False
                break
        return all_contained

    def select_files(self, filenames: List[str]) -> SourceLines:
        res = SourceLines()
        for filename in filenames:
            if filename in self.files2lines:
                res.files2lines[filename].update(self.files2lines[filename])
        return res
        
    def from_dict(d: Dict) -> SourceLines:
        res = SourceLines()
        for filename, lines in d.items():
            res.files2lines[filename].update(lines)
        return res

    def count(self) -> int:
        cnt = 0
        for lines in self.files2lines.values():
            cnt += len(lines)
        return cnt

    def to_filelines(self, filename) -> FileLines:
        return FileLines(filename=filename, lines=list(self.files2lines[filename]))

    def print(self) -> str:
        reprs = []
        for filename, lines in self.files2lines.items():
            if len(lines) > 0:
                reprs.append(f"{filename}({', '.join([str(line) for line in lines])})")
        return '\n'.join(reprs)
