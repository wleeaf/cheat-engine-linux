#!/usr/bin/env python3
"""Check that the Qt translation catalogues in translations/ are complete.

Every <message> must have a finished translation, and the %n / %1..%9
placeholders of the source must also appear in the translation. Used by CI so
a new tr() string cannot land without its translation.

Usage: python3 tools/check-translations.py
Exits non-zero (prints FAILED) when a catalogue is incomplete.
"""
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

PLACEHOLDER = re.compile(r'%(?:n|\d{1,3})')

def placeholders(text: str) -> set[str]:
    return set(PLACEHOLDER.findall(text or ''))

def check(path: str) -> list[str]:
    errors = []
    tree = ET.parse(path)
    language = tree.getroot().get('language') or os.path.basename(path).split('_')[-1].split('.')[0]
    for context in tree.getroot().findall('context'):
        name = context.findtext('name') or '?'
        for message in context.findall('message'):
            source = message.findtext('source') or ''
            translation = message.find('translation')
            if translation is None or translation.get('type') == 'unfinished':
                errors.append(f"{path}: {name}: unfinished: {source!r}")
                continue
            if not (translation.text or '').strip():
                errors.append(f"{path}: {name}: empty translation: {source!r}")
                continue
            if message.get('numerus') == 'yes':
                forms = [form.text or '' for form in translation.findall('numerusform')]
                if not forms or any(not form.strip() for form in forms):
                    errors.append(f"{path}: {name}: unfinished plural: {source!r}")
                continue
            missing = placeholders(source) - placeholders(translation.text)
            if missing:
                errors.append(f"{path}: {name}: translation drops {sorted(missing)}: {source!r}")
    print(f"{path}: language={language} OK")
    return errors

def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    catalogues = sorted(glob.glob(os.path.join(root, 'translations', '*.ts')))
    if not catalogues:
        print("FAILED: no translation catalogues under translations/")
        return 1
    errors = []
    for path in catalogues:
        try:
            errors.extend(check(os.path.relpath(path, root)))
        except ET.ParseError as error:
            errors.append(f"{path}: invalid XML: {error}")
    if errors:
        for error in errors:
            print(f"  {error}")
        print(f"FAILED: {len(errors)} translation problem(s)")
        return 1
    print("Translations complete")
    return 0

if __name__ == '__main__':
    sys.exit(main())
