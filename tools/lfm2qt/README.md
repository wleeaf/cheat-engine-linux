# lfm2qt — Cheat Engine `.lfm` → Qt `.ui` transpiler + feature inventory

Cheat Engine's GUI is defined in Lazarus `.lfm` form files (declarative layouts,
like Qt `.ui`). This tool reads them **as a reference** and emits:

- **`.ui` layouts** — our own Qt Designer files reproducing CE's control tree and
  geometry, so ported windows look like CE. `uic`-compilable.
- **A feature inventory** (`docs/CE_FEATURE_INVENTORY.md`) — every window's
  controls + event handlers, i.e. the checklist of what our Qt GUI still lacks.

## Clean-room boundary

We do **not** vendor CE's `.lfm`/`.pas` or its icons. The tool reads a CE checkout
kept **outside this repo**; only our own generated layouts + the factual inventory
are produced. Event *logic* (CE's Pascal handlers) is never transpiled — generated
forms expose stub slot names that we wire to our own backend.

## Usage

```sh
# 1. Get a CE checkout somewhere outside this repo (reference input):
git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/cheat-engine/cheat-engine ../ce-upstream-ref
( cd ../ce-upstream-ref && git sparse-checkout set "Cheat Engine" )

# 2. Generate layouts + the inventory:
python3 tools/lfm2qt/lfm2qt.py \
    --ce-source "../ce-upstream-ref/Cheat Engine" \
    --out-ui   gui/generated \
    --out-report docs/CE_FEATURE_INVENTORY.md
```

The generated `gui/generated/*.ui` are **gitignored** (regenerate on demand). To
use one in the app, run `uic` on it (or add it to a Qt target) and write a
companion class that wires its controls to our backend.

## Pieces

- `lfm_parser.py` — parses `.lfm` into a typed object tree (handles strings, sets,
  collections, string-lists; skips image blobs).
- `widget_map.py` — LCL control type → Qt widget class; non-visual components.
- `gen_ui.py` — object tree → Qt `.ui` XML (parent-relative geometry, text, items,
  menus).
- `lfm2qt.py` — driver: generate all `.ui` + write the Markdown inventory.
