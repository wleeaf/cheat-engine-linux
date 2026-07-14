#!/usr/bin/env python3
"""Generate docs/GUI_PARITY.md: the tracked CE-vs-ours GUI gap checklist.

Reads a CE upstream checkout (the .lfm forms are the authoritative UI spec) and
emits, per window, CE's control/handler/menu counts alongside our corresponding
Qt window, plus the exact main-menu tree. Regenerate whenever we close gaps:

    python3 tools/lfm2qt/gui_parity.py --ce-source "../ce-upstream-ref/Cheat Engine"
"""
import sys, os, glob, argparse
sys.path.insert(0, os.path.dirname(__file__))
from lfm_parser import parse_lfm_file

# CE form (unit basename)  ->  (our gui/ file or "" if none, note)
# "" our-file means no equivalent yet. "N/A:<reason>" marks platform-gated forms
# that a Linux build does not show (Windows/DBVM/Direct3D/.NET-on-Windows only).
MAP = {
    "MainUnit": ("mainwindow", ""),
    "frmStringPointerScanUnit": ("mainwindow", ""),
    "frmgroupscanalgoritmgeneratorunit": ("mainwindow", ""),
    "frmchangedaddressescommonalityscannerunit": ("structuredissector", "N-instance field compare = commonality"),
    "codefiltercalloralldialog": ("codereferences", "call/all filter subset"),
    "frmcodefilterunit": ("codereferences", "code categorized by type (calls/jumps/strings tabs)"),
    "frmexceptionignorelistunit": ("debuggerwindow", "break-on-signals; no ignore list"),
    "frmexceptionregionlistunit": ("debuggerwindow", "break-on-signals; no per-region list"),
    "formChangedAddresses": ("mainwindow", "changed/unchanged scan covers this"),
    "frmExcludeHideUnit": ("settingsdialog", "scan region filtering"),
    "frmfoundlistpreferencesunit": ("mainwindow", "basic result display only"),
    "frmStringMapUnit": ("codereferences", ""),
    "celistviewitemeditor": ("mainwindow", ""),
    "frmopenfileasprocessdialogunit": ("mainwindow", ""),
    "formPointerOrPointeeUnit": ("pointerscan_dialog", ""),
    "frmdebugsymbolstructurelistunit": ("structuredissector", ""),
    "frmsourcedisplayunit": ("memorybrowser", ""),
    "gdbserverconnectdialog": ("mainwindow", ""),
    "frmassemblyscanunit": ("mainwindow", ""),
    "frmfinddialogunit": ("memorybrowser", ""),
    "frmBreakThreadUnit": ("threadlist", ""),
    "frmFloatingPointPanelUnit": ("debuggerwindow", ""),
    "frmBreakpointConditionUnit": ("breakpointlist", ""),
    "frmautoinjectunit": ("scripteditor", ""),
    "frmsyntaxhighlightereditor": ("scripteditor", ""),
    "frmAAEditPrefsUnit": ("scripteditor", ""),
    "frmanchoreditor": ("formdesigner", ""),
    "frmrearrangestructurelistunit": ("structuredissector", ""),
    "frmStructureLinkerUnit": ("structuredissector", ""),
    "frmstructuresnewstructureunit": ("structuredissector", ""),
    "frmstructuresnewstructure": ("structuredissector", ""),
    "inputboxtopunit": ("mainwindow", ""),
    "multilineinputqueryunit": ("mainwindow", ""),
    "frmLoadMemoryunit": ("mainwindow", ""),
    "frmSortPointerlistUnit": ("pointerscan_dialog", ""),
    "frmProcesswatcherExtraUnit": ("mainwindow", ""),
    "frmmanualstacktraceconfigunit": ("stackview", ""),
    "frmnetworkdatacompressionunit": ("settingsdialog", ""),
    "frmWatchListAddEntryUnit": ("mainwindow", ""),
    "frmmemreccomboboxunit": ("mainwindow", ""),
    "formhotkeyunit": ("globalhotkeys", ""),
    "frmHotkeyExUnit": ("globalhotkeys", ""),
    "frmsnapshothandlerUnit": ("mainwindow", ""),
    "frmSaveSnapshotsUnit": ("mainwindow", ""),
    "frmCodecaveScannerUnit": ("codereferences", ""),
    "frmSetCrosshairUnit": ("overlay", ""),
    "Changeoffsetunit": ("changeaddressdialog", ""),
    "formAddToCodeList": ("advancedoptions", ""),
    "formAddressChange": ("changeaddressdialog", ""),
    "ThreadlistExFRM": ("threadlist", ""),
    "frmDisassemblyscanunit": ("mainwindow", ""),
    "frmWatchlistUnit": ("mainwindow", ""),
    "frmProcessWatcherUnit": ("mainwindow", ""),
    "frmreferencedfunctionsunit": ("codereferences", ""),
    "frmReferencedStringsUnit": ("codereferences", ""),
    "frmHeapsUnit": ("heapregions", ""),
    "frmstacktraceunit": ("stackview", ""),
    "StructuresAddElementfrm": ("structuredissector", ""),
    "StructuresFrm2": ("structuredissector", ""),
    "frmDissectwindowUnit": ("structuredissector", ""),
    "frmBreakpointlistunit": ("breakpointlist", ""),
    "frmbranchmapperunit": ("branchmapper", ""),
    "frmFilePatcherUnit": ("filepatcher", ""),
    "frmFillMemoryUnit": ("memoryfill", ""),
    "frmresumepointerscanunit": ("pointerscan_dialog", ""),
    "frmStructPointerRescanUnit": ("pointerscan_dialog", ""),
    "frmRescanPointerUnit": ("pointerscan_dialog", ""),
    "frmMemoryAllocHandlerUnit": ("mainwindow", ""),
    "symbolconfigunit": ("settingsdialog", ""),
    "networkConfig": ("settingsdialog", ""),
    "PasteTableentryFRM": ("mainwindow", ""),
    "frmStructures2ElementInfoUnit": ("structuredissector", ""),
    "TypePopup": ("mainwindow", ""),
    "accessedmemory": ("codefinder", ""),
    "asktorunluascript": ("mainwindow", ""),
    "savedisassemblyfrm": ("mainwindow", ""),
    "frmMemoryViewExUnit": ("graphicalmemoryview", ""),
    "frmluaengineunit": ("luaconsole", ""),
    "frmFindstaticsUnit": ("findstaticswindow", ""),
    "ProcessWindowUnit": ("processlistdialog", ""),
    "frmmemoryrecorddropdownsettingsunit": ("mainwindow", ""),
    "frmSaveMemoryRegionUnit": ("mainwindow", ""),
    "formProcessInfo": ("mainwindow", ""),
    "AdvancedOptionsUnit": ("advancedoptions", ""),  # Code list
    "MemoryBrowserFormUnit": ("memorybrowser", "CE layout: disasm+registers / hex+stacktrace, debug toolbar, own File/Search/View/Debug/Tools menu bar; in-window single-stepping pending (use Debugger window)"),
    "formsettingsunit": ("settingsdialog", ""),  # all CE tabs present
    "pointerscannerfrm": ("pointerscan_dialog", ""),
    "PointerscannerSettingsFrm": ("pointerscan_dialog", "scan options"),
    "FoundCodeUnit": ("codefinder", "what-writes/accesses result list"),
    "formFoundcodeListExtraUnit": ("codefinder", ""),
    "formmemoryregionsunit": ("memoryregions", ""),
    "frmThreadlistunit": ("threadlist", ""),
    "frmRegistersunit": ("registereditor", ""),
    "frmModifyRegistersUnit": ("registereditor", "edit register value"),
    "formdesignerunit": ("formdesigner", ""),
    "Structuresfrm": ("structuredissector", ""),
    "frmstructuresconfigunit": ("structuredissector", "dissect config"),
    "frmstructurecompareunit": ("structuredissector", "compare instances"),
    "frmTracerUnit": ("tracerwindow", ""),
    "frmTracerConfigUnit": ("tracerwindow", "break-and-trace config"),
    "CommentsUnit": ("mainwindow", ""),  # Table Extras -> Comments memo
    "aboutunit": ("mainwindow", "inline About box only"),
    "PEInfounit": ("elfinspector", "ELF inspector vs CE's PE info"),
    "HotKeys": ("globalhotkeys", "set/change hotkey"),
    "frameHotkeyConfigUnit": ("globalhotkeys", ""),
    "trainergenerator": ("mainwindow", ""),
    "frmExeTrainerGeneratorUnit": ("mainwindow", ""),
    "frmMemviewPreferencesUnit": ("memviewpreferences", ""),
    "frmModuleListUnit": ("modulelist", ""),
    "frmStackViewUnit": ("stackview", ""),
    "DissectCodeunit": ("codereferences", ""),
    "formAddressChangeUnit": ("changeaddressdialog", ""),
    "HexViewPreferences": ("", ""),
}
# platform-gated form-name substrings a Linux build hides
NA = {
    "dbvm": "DBVM (hypervisor) only", "D3D": "Direct3D (Windows) only",
    "d3d": "Direct3D (Windows) only", "Kernel": "Windows kernel driver",
    "psn": "distributed pointerscan node",
    "pointerscanconnect": "distributed pointerscan (network)",
    "pointerrescanconnect": "distributed pointerscan (network)",
    "mergepointerscan": "distributed pointerscan (network)", "Ultimap": "Intel PT / Windows only",
    "ultimap": "Intel PT / Windows only", "dotnet": ".NET (Windows) only",
    "Vehdebug": "VEH debugger (Windows) only",
    "DifferentBitSize": "internal bit-size warning",
    "BusyUnit": "generic busy/progress dialog",
    "Valuechange": "value-change helper",
    "edithistory": "edit-history (minor)",
    "selectionlist": "generic selection helper",
    "FindWindow": "find target GUI window (niche)",
    "bogus": "test form",
    "AdConfig": "Support-CE donation dialog",
    "ModuleSafety": "Windows module-safety",
    "microtransaction": "Windows-specific",
    "CapturedTimers": "Windows timers",
    "tlgUnit": "trace-log (Windows)",
    "DebugStrings": "OutputDebugString capture (Windows)",
    "driverlist": "Windows driver list",
    "debuggerattachtimeout": "attach-timeout (minor)",
    "symboleventtakinglong": "symbol-load progress (minor)",
    "cr3": "DBVM CR3 switcher (hypervisor)",
    "GDT": "Windows GDT (kernel)",
    "IDT": "Windows IDT (kernel)",
    "Paging": "Windows paging (kernel/DBVM)",
    "ServiceDescriptor": "Windows SSDT (kernel)",
    "Driver": "Windows driver management",
    "EnumerateDLL": "Windows DLL enumeration",
    "APIhook": "Windows API hook",
    "iptlog": "Intel PT / Ultimap (Windows)",
    "DebugEvents": "Windows debug events",
}

def cap_of(o):
    c = o.props.get("Caption"); return c if isinstance(c, str) else ""

def menu_tree(node, depth, out):
    for ch in node.children:
        if ch.type != "TMenuItem": menu_tree(ch, depth, out); continue
        c = cap_of(ch)
        out.append("  "*depth + ("——" if c == "-" else (c or f"<{ch.name}>")))
        menu_tree(ch, depth+1, out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ce-source", required=True)
    ap.add_argument("--out", default="docs/GUI_PARITY.md")
    a = ap.parse_args()

    forms = []
    main_menu = []
    for f in sorted(glob.glob(os.path.join(a.ce_source, "*.lfm"))):
        try: root = parse_lfm_file(f)
        except Exception: continue
        name = os.path.basename(f)[:-4]
        nodes = list(root.walk())
        skip = ("TMainMenu","TPopupMenu","TMenuItem","TAction","TImageList","TTimer","TIdGlobal")
        ctrls = sum(1 for n in nodes if n is not root and not n.type.startswith(skip))
        hdlrs = sum(len([k for k in n.props if k.startswith("On")]) for n in nodes)
        menus = sum(1 for n in nodes if n.type == "TMenuItem")
        forms.append((name, cap_of(root), ctrls, hdlrs, menus))
        if name == "MainUnit":
            for n in nodes:
                if n.name == "MainMenu1": menu_tree(n, 0, main_menu); break
    forms.sort(key=lambda r: -r[2])

    L = []
    L.append("# GUI parity checklist (Cheat Engine → our Qt GUI)\n")
    L.append("Auto-generated by `tools/lfm2qt/gui_parity.py` from CE's `.lfm` forms")
    L.append("(the authoritative UI spec). Regenerate after closing gaps. CE's `.lfm`")
    L.append("+ `.pas` are read as *reference*; we reimplement clean (MIT, not GPL).\n")
    L.append("Legend: ✅ have · ⚠️ partial · ❌ missing · 🚫 N/A on Linux\n")

    L.append("## Main menu bar (`MainUnit` → our `mainwindow.cpp`)\n")
    L.append("CE's exact top-menu tree. `—` = separator. (Windows-only entries like")
    L.append("D3D/.Net are hidden on a Linux build.)\n")
    L.append("```")
    L.extend(main_menu)
    L.append("```\n")

    L.append("## Window coverage (every CE form, largest first)\n")
    L.append("| CE form | Caption | ctrls | hdlrs | menus | Our window | Status |")
    L.append("|---|---|---:|---:|---:|---|---|")
    for name, cap, c, h, m in forms:
        na = next((r for k, r in NA.items() if k in name), None)
        ours, note = MAP.get(name, ("", ""))
        if na and not ours:
            status, our = "🚫 " + na, "—"
        elif not ours:
            status, our = "❌ missing", "—"
        elif note and ("MISSING" in note or "missing" in note):
            status, our = "⚠️ " + note, f"`{ours}`"
        elif note:
            status, our = "⚠️ " + note, f"`{ours}`"
        else:
            status, our = "✅", f"`{ours}`"
        L.append(f"| {name} | {cap[:34]} | {c} | {h} | {m} | {our} | {status} |")

    have = sum(1 for r in L if "| ✅" in r or "| ⚠️" in r)
    L.insert(4, f"**{len(forms)} CE forms.** Regenerated coverage below.\n")
    with open(a.out, "w") as fh: fh.write("\n".join(L) + "\n")
    print(f"wrote {a.out}: {len(forms)} forms, {len(main_menu)} menu lines")

if __name__ == "__main__":
    main()
