"""Parser for Lazarus .lfm form files (Cheat Engine's GUI definitions).

An .lfm is a declarative form tree:

    object MainForm: TMainForm
      Caption = 'Cheat Engine'
      object Panel1: TPanel
        Align = alClient
        object btnScan: TButton
          Caption = 'First Scan'
          OnClick = btnScanClick
        end
      end
    end

This produces a tree of LfmObject nodes with typed property values. It is used
purely as a *reference* to reimplement CE's layout in our own Qt: we read CE's
.lfm files (kept outside this repo) and emit our own .ui + a feature inventory.
No CE code or art is copied — image blobs (`.Data = { ... }`) are skipped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LfmObject:
    name: str
    type: str
    kind: str = "object"                       # object | inherited | inline
    props: dict[str, Any] = field(default_factory=dict)
    children: list["LfmObject"] = field(default_factory=list)

    def walk(self):
        """Yield this node and all descendants (pre-order)."""
        yield self
        for c in self.children:
            yield from c.walk()


# Sentinels for value kinds we keep structured rather than flattening to str.
@dataclass
class LfmSet:
    items: list[str]


@dataclass
class LfmCollection:
    items: list[dict[str, Any]]


class _Scanner:
    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.n = len(text)

    # ---- low-level cursor helpers ----
    def _skip_ws(self):
        while self.i < self.n:
            c = self.s[self.i]
            if c in " \t\r\n":
                self.i += 1
            else:
                break

    def _peek_word(self) -> str:
        self._skip_ws()
        j = self.i
        while j < self.n and (self.s[j].isalnum() or self.s[j] in "_."):
            j += 1
        return self.s[self.i:j]

    def _read_word(self) -> str:
        self._skip_ws()
        j = self.i
        while j < self.n and (self.s[j].isalnum() or self.s[j] in "_."):
            j += 1
        w = self.s[self.i:j]
        self.i = j
        return w

    def _read_to_eol(self) -> str:
        j = self.s.find("\n", self.i)
        if j < 0:
            j = self.n
        line = self.s[self.i:j]
        self.i = j
        return line

    # ---- value parsing ----
    def _read_string(self) -> str:
        # Pascal string: 'text', '' escapes a quote, and 'a' + 'b' or 'a' #13 'b'
        # continuations concatenate. #NN are character codes.
        out = []
        while True:
            self._skip_ws()
            if self.i >= self.n:
                break
            c = self.s[self.i]
            if c == "'":
                self.i += 1
                buf = []
                while self.i < self.n:
                    ch = self.s[self.i]
                    if ch == "'":
                        if self.i + 1 < self.n and self.s[self.i + 1] == "'":
                            buf.append("'")
                            self.i += 2
                            continue
                        self.i += 1
                        break
                    buf.append(ch)
                    self.i += 1
                out.append("".join(buf))
            elif c == "#":
                self.i += 1
                num = []
                while self.i < self.n and self.s[self.i].isdigit():
                    num.append(self.s[self.i])
                    self.i += 1
                if num:
                    out.append(chr(int("".join(num))))
            elif c == "+":
                self.i += 1
                continue
            else:
                break
            # Peek for a continuation (+, another quote, or #code) on this/next line.
            save = self.i
            self._skip_ws()
            if self.i < self.n and self.s[self.i] in "'#+":
                continue
            self.i = save
            break
        return "".join(out)

    def _read_bracketed(self, open_ch: str, close_ch: str) -> str:
        # Consume a balanced [...] / (...) / {...} region, returning the inner text.
        assert self.s[self.i] == open_ch
        depth = 0
        j = self.i
        in_str = False
        while j < self.n:
            ch = self.s[j]
            if in_str:
                if ch == "'":
                    in_str = False
            elif ch == "'":
                in_str = True
            elif ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    inner = self.s[self.i + 1:j]
                    self.i = j + 1
                    return inner
            j += 1
        inner = self.s[self.i + 1:]
        self.i = self.n
        return inner

    def _read_collection(self) -> LfmCollection:
        # < item ... end item ... end >
        assert self.s[self.i] == "<"
        self.i += 1
        items: list[dict[str, Any]] = []
        while True:
            self._skip_ws()
            if self.i >= self.n or self.s[self.i] == ">":
                self.i += 1
                break
            w = self._peek_word()
            if w.lower() == "item":
                self._read_word()  # consume 'item'
                item: dict[str, Any] = {}
                while True:
                    self._skip_ws()
                    nxt = self._peek_word()
                    if nxt.lower() == "end":
                        self._read_word()
                        break
                    if self.i >= self.n or self.s[self.i] == ">":
                        break
                    pname = self._read_word()
                    self._skip_ws()
                    if self.i < self.n and self.s[self.i] == "=":
                        self.i += 1
                        item[pname] = self._read_value()
                items.append(item)
            else:
                # Malformed / unexpected; bail to the closing '>'.
                self._read_to_eol()
        return LfmCollection(items)

    def _read_value(self) -> Any:
        self._skip_ws()
        if self.i >= self.n:
            return None
        c = self.s[self.i]
        if c == "'" or c == "#":
            return self._read_string()
        if c == "[":
            inner = self._read_bracketed("[", "]")
            items = [x.strip() for x in inner.replace("\n", " ").split(",") if x.strip()]
            return LfmSet(items)
        if c == "(":
            inner = self._read_bracketed("(", ")")
            # A list of quoted strings and/or bare tokens.
            sub = _Scanner(inner)
            vals: list[Any] = []
            while True:
                sub._skip_ws()
                if sub.i >= sub.n:
                    break
                if sub.s[sub.i] in "'#":
                    vals.append(sub._read_string())
                else:
                    w = sub._read_word()
                    if not w:
                        sub.i += 1
                        continue
                    vals.append(w)
            return vals
        if c == "{":
            # Binary blob (image data etc.) — skip, never copied.
            self._read_bracketed("{", "}")
            return "<binary-skipped>"
        if c == "<":
            return self._read_collection()
        # Bareword: number, True/False, or identifier/enum/handler.
        word = self._read_word()
        low = word.lower()
        if low == "true":
            return True
        if low == "false":
            return False
        try:
            return int(word)
        except ValueError:
            pass
        try:
            return float(word)
        except ValueError:
            pass
        return word  # identifier / enum / event handler name

    # ---- object parsing ----
    def parse_object(self) -> LfmObject | None:
        self._skip_ws()
        kind = self._peek_word().lower()
        if kind not in ("object", "inherited", "inline"):
            return None
        self._read_word()  # consume kind
        header = self._read_to_eol().strip()  # "Name: TType" (or just "TType")
        if ":" in header:
            name, typ = header.split(":", 1)
            name, typ = name.strip(), typ.strip()
        else:
            name, typ = "", header.strip()
        # A trailing "[N]" index (for arrays) is noise for our purposes.
        typ = typ.split("[", 1)[0].strip()
        node = LfmObject(name=name, type=typ, kind=kind)

        while True:
            self._skip_ws()
            if self.i >= self.n:
                break
            w = self._peek_word()
            lw = w.lower()
            if lw == "end":
                self._read_word()
                break
            if lw in ("object", "inherited", "inline"):
                child = self.parse_object()
                if child:
                    node.children.append(child)
                continue
            # property: Name = Value
            pname = self._read_word()
            if not pname:
                self.i += 1
                continue
            self._skip_ws()
            if self.i < self.n and self.s[self.i] == "=":
                self.i += 1
                node.props[pname] = self._read_value()
            else:
                # Unexpected token; skip the line to stay robust.
                self._read_to_eol()
        return node


def parse_lfm(text: str) -> LfmObject:
    # .lfm files may start with a BOM or leading whitespace.
    return _Scanner(text.lstrip("﻿")).parse_object()


def parse_lfm_file(path: str) -> LfmObject:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return parse_lfm(f.read())


if __name__ == "__main__":
    import sys
    root = parse_lfm_file(sys.argv[1])

    def show(node: LfmObject, depth: int = 0):
        pad = "  " * depth
        cap = node.props.get("Caption")
        cap = f" caption={cap!r}" if isinstance(cap, str) else ""
        handlers = [k for k in node.props if k.startswith("On")]
        h = f" handlers={handlers}" if handlers else ""
        print(f"{pad}{node.name}: {node.type}{cap}{h}")
        for c in node.children:
            show(c, depth + 1)

    show(root)
    total = sum(1 for _ in root.walk())
    print(f"\n[{total} controls]")
