"""Generate a Qt Designer .ui from a parsed .lfm tree.

Faithful-look strategy: LCL controls store parent-relative Left/Top/Width/Height,
which map directly to Qt's parent-relative widget geometry, so emitting each
control at its stored rect reproduces CE's design-time layout at the default size.
(Delphi Align/Anchors resize behaviour is a later refinement.) Non-visual
components are skipped; a TMainMenu becomes a QMenuBar. Text/items/tooltip/enabled
carry over. This output is OUR layout artifact — no CE code or art is embedded.
"""

from __future__ import annotations

import html

from lfm_parser import LfmObject
from widget_map import qt_class, is_nonvisual


def _esc(s: str) -> str:
    return html.escape(str(s), quote=False)


def _int(v, default: int = 0) -> int:
    try:
        return int(v)
    except (ValueError, TypeError):
        try:
            return int(float(v))
        except (ValueError, TypeError):
            return default


def _geom(node: LfmObject) -> str:
    x = _int(node.props.get("Left", 0))
    y = _int(node.props.get("Top", 0))
    w = _int(node.props.get("Width", 100), 100)
    h = _int(node.props.get("Height", 24), 24)
    return (f'<property name="geometry"><rect>'
            f'<x>{x}</x><y>{y}</y>'
            f'<width>{w}</width><height>{h}</height></rect></property>')


# Qt classes that actually have a `text` property (setText). Others use title
# (QGroupBox), items (combos/lists), or are containers with no caption.
_TEXT_WIDGETS = {"QLabel", "QPushButton", "QToolButton", "QCheckBox",
                 "QRadioButton", "QLineEdit"}


def _text_prop(qt: str, node: LfmObject) -> list[str]:
    out: list[str] = []
    cap = node.props.get("Caption")
    if cap is None and qt == "QLineEdit":
        cap = node.props.get("Text")
    if qt in _TEXT_WIDGETS and isinstance(cap, str) and cap != "<binary-skipped>":
        out.append(f'<property name="text"><string>{_esc(cap)}</string></property>')
    hint = node.props.get("Hint")
    if isinstance(hint, str) and hint:
        out.append(f'<property name="toolTip"><string>{_esc(hint)}</string></property>')
    if node.props.get("Enabled") is False:
        out.append('<property name="enabled"><bool>false</bool></property>')
    if node.props.get("Visible") is False:
        out.append('<property name="visible"><bool>false</bool></property>')
    if node.props.get("Checked") is True and qt in ("QCheckBox", "QRadioButton"):
        out.append('<property name="checked"><bool>true</bool></property>')
    return out


def _combo_items(node: LfmObject) -> list[str]:
    items = node.props.get("Items.Strings") or node.props.get("Items")
    if not isinstance(items, list):
        return []
    out = []
    for it in items:
        if isinstance(it, str):
            out.append(f'<item><property name="text"><string>{_esc(it)}</string></property></item>')
    return out


def _emit_widget(node: LfmObject, out: list[str], indent: int) -> None:
    qt = qt_class(node.type)
    if qt is None:
        # Non-visual (or splitter): don't emit, but recurse so nested visual
        # children of an unexpected container aren't lost.
        for c in node.children:
            _emit_widget(c, out, indent)
        return

    pad = "  " * indent
    name = node.name or f"{node.type[1:].lower()}"
    out.append(f'{pad}<widget class="{qt}" name="{_esc(name)}">')
    out.append(f"{pad}  {_geom(node)}")
    for p in _text_prop(qt, node):
        out.append(f"{pad}  {p}")
    for it in _combo_items(node):
        out.append(f"{pad}  {it}")
    if qt == "QGroupBox":
        title = node.props.get("Caption")
        if isinstance(title, str):
            out.append(f'{pad}  <property name="title"><string>{_esc(title)}</string></property>')
    for c in node.children:
        _emit_widget(c, out, indent + 1)
    out.append(f"{pad}</widget>")


def _find_menu(root: LfmObject) -> LfmObject | None:
    for c in root.children:
        if c.type == "TMainMenu":
            return c
    return None


def _emit_menu(menu: LfmObject, out: list[str], actions: list[str]) -> None:
    out.append('  <widget class="QMenuBar" name="menubar">')

    def emit_item(item: LfmObject, depth: int):
        cap = item.props.get("Caption", "")
        if cap == "-":
            return  # separator handled by ordering; skip a named widget
        has_children = any(ch.type == "TMenuItem" for ch in item.children)
        pad = "    " + "  " * depth
        if has_children:
            out.append(f'{pad}<widget class="QMenu" name="{_esc(item.name)}">')
            out.append(f'{pad}  <property name="title"><string>{_esc(cap)}</string></property>')
            for ch in item.children:
                if ch.type == "TMenuItem":
                    emit_item(ch, depth + 1)
            out.append(f"{pad}</widget>")
        else:
            actions.append(item.name)

    for top in menu.children:
        if top.type == "TMenuItem":
            emit_item(top, 0)
    out.append("  </widget>")


def generate_ui(root: LfmObject) -> str:
    is_main = "Menu" in root.props or _find_menu(root) is not None
    base = "QMainWindow" if is_main else "QWidget"
    name = root.name or "Form"

    body: list[str] = []
    body.append('<?xml version="1.0" encoding="UTF-8"?>')
    body.append('<ui version="4.0">')
    body.append(f" <class>{_esc(name)}</class>")
    body.append(f' <widget class="{base}" name="{_esc(name)}">')
    body.append(f"  {_geom_form(root)}")
    cap = root.props.get("Caption")
    if isinstance(cap, str):
        body.append(f'  <property name="windowTitle"><string>{_esc(cap)}</string></property>')

    container_open = "  " * 1
    if base == "QMainWindow":
        body.append(f'{container_open}<widget class="QWidget" name="centralwidget">')
        for c in root.children:
            if c.type != "TMainMenu":
                _emit_widget(c, body, 2)
        body.append(f"{container_open}</widget>")
        menu = _find_menu(root)
        if menu is not None:
            actions: list[str] = []
            _emit_menu(menu, body, actions)
    else:
        for c in root.children:
            _emit_widget(c, body, 2)

    body.append(" </widget>")
    body.append(" <resources/>")
    body.append(" <connections/>")
    body.append("</ui>")
    return "\n".join(body) + "\n"


def _geom_form(node: LfmObject) -> str:
    w = _int(node.props.get("Width", 640), 640)
    h = _int(node.props.get("Height", 480), 480)
    return (f'<property name="geometry"><rect>'
            f'<x>0</x><y>0</y><width>{w}</width><height>{h}</height></rect></property>')
