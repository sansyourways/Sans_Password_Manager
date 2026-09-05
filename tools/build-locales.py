#!/usr/bin/env python3
"""Fold locales/*.json into the generated region of src/spm_web_server.py.

Translators edit JSON. Nothing else. The catalogues used to live in a
JavaScript object literal inside a Python triple-quoted string inside a file
concatenated into a generated shell script, which meant a contributor adding a
language had to get Python-level escaping right inside someone else's literal.
The regression suite carried a test whose only job was to catch that escaping
going wrong, which said plainly enough that the format was the problem.

The region this writes is committed, and `./build.sh --check` verifies it is
current -- the same discipline spm.sh itself is held to.
"""

import ast
import io
import json
import os
import sys

BEGIN = "# --- BEGIN GENERATED LOCALES ---"
END = "# --- END GENERATED LOCALES ---"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Overridable so the regression suite can point this at a deliberately broken
# catalogue and confirm it refuses. The generator carries its own copy of the
# flag rule because it is the thing that writes source code, and a rule that
# only the lint enforces is one a direct invocation walks straight past.
LOCALE_DIR = os.environ.get("SPM_LOCALE_DIR") or os.path.join(ROOT, "locales")
TARGET = os.path.join(ROOT, "src", "spm_web_server.py")

REVIEWS = ("maintained", "unreviewed")
# A flag is exactly two regional indicator symbols. Checked rather than trusted
# because anything else in that field renders as stray text in the middle of a
# picker: a plain emoji, a two-letter string, an empty value. And a flag is a
# country while a language is not, so the field is deliberately not derived
# from the code -- someone chose it, and someone can argue with the choice.
FLAG_RANGE = range(0x1F1E6, 0x1F200)
DIRECTIONS = ("ltr", "rtl")


def load():
    """Read every catalogue, refusing anything the dashboard could not serve."""
    if not os.path.isdir(LOCALE_DIR):
        sys.exit("locales/ is missing")
    codes = sorted(
        name[:-5] for name in os.listdir(LOCALE_DIR) if name.endswith(".json"))
    if "en" not in codes:
        sys.exit("locales/en.json is the key set every other catalogue is "
                 "checked against, and it is missing")
    # English first so the fallback is the first thing a reader of the
    # generated region meets, then the rest in a stable order.
    codes = ["en"] + [code for code in codes if code != "en"]

    locales, catalogues = {}, {}
    for code in codes:
        path = os.path.join(LOCALE_DIR, "%s.json" % code)
        with io.open(path, encoding="utf-8") as handle:
            try:
                doc = json.load(handle)
            except ValueError as exc:
                sys.exit("%s.json is not valid JSON: %s" % (code, exc))
        meta = doc.get("meta")
        strings = doc.get("strings")
        if not isinstance(meta, dict) or not isinstance(strings, dict):
            sys.exit("%s.json needs a 'meta' object and a 'strings' object"
                     % code)
        if meta.get("code") != code:
            sys.exit("%s.json declares code %r, which does not match its "
                     "filename" % (code, meta.get("code")))
        for field in ("name", "english_name", "flag", "dir", "review"):
            if not meta.get(field):
                sys.exit("%s.json is missing meta.%s" % (code, field))
        if meta["dir"] not in DIRECTIONS:
            sys.exit("%s.json declares dir %r; expected one of %s"
                     % (code, meta["dir"], ", ".join(DIRECTIONS)))
        if meta["review"] not in REVIEWS:
            sys.exit("%s.json declares review %r; expected one of %s"
                     % (code, meta["review"], ", ".join(REVIEWS)))
        flag = meta["flag"]
        if len(flag) != 2 or any(ord(ch) not in FLAG_RANGE for ch in flag):
            sys.exit("%s.json declares flag %r; expected two regional "
                     "indicator symbols" % (code, flag))
        for key, value in strings.items():
            if not isinstance(value, str):
                sys.exit("%s.json: %s is not a string" % (code, key))
        locales[code] = {
            "name": meta["name"],
            "english_name": meta["english_name"],
            "flag": meta["flag"],
            "dir": meta["dir"],
            "review": meta["review"],
        }
        catalogues[code] = strings

    english = set(catalogues["en"])
    for code in codes:
        if code == "en":
            continue
        absent = english - set(catalogues[code])
        extra = set(catalogues[code]) - english
        if absent:
            sys.exit("%s is missing %d key(s), e.g. %s"
                     % (code, len(absent), sorted(absent)[0]))
        if extra:
            sys.exit("%s has %d key(s) English does not, e.g. %s"
                     % (code, len(extra), sorted(extra)[0]))
    return codes, locales, catalogues


def py(value):
    """A string as a double-quoted ASCII Python literal.

    Not json.dumps. Its ensure_ascii writes an astral character as a surrogate
    pair -- "\\ud83c\\uddec" -- which is valid JSON and, in Python source, two
    lone surrogates that never combine and cannot even be encoded to UTF-8. The
    region is Python, so it is written with Python's own escaping, which emits
    \\U0001f1ec and means the character. Found by the first value in this
    project to leave the BMP: a flag in the language picker.

    Not ascii() either, which quotes with whichever mark keeps the literal
    shortest. The region has been double-quoted since it was introduced and
    things grep it; re-quoting every line would bury one real change under
    four thousand cosmetic ones.
    """
    out = ['"']
    for ch in value:
        point = ord(ch)
        if ch in ('"', "\\"):
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif 0x20 <= point < 0x7F:
            out.append(ch)
        elif point <= 0xFFFF:
            out.append("\\u%04x" % point)
        else:
            out.append("\\U%08x" % point)
    out.append('"')
    return "".join(out)


def render(codes, locales, catalogues):
    """Emit the region.

    Every value is written as an ASCII Python literal, which keeps the
    generated source ASCII the way the hand-written dictionaries were.
    """
    out = [
        BEGIN,
        "# Generated by tools/build-locales.py from locales/*.json.",
        "# Do not edit by hand -- edit the JSON and rebuild. `./build.sh --check`",
        "# verifies this region is current.",
        "WEB_LOCALES = {",
    ]
    for code in codes:
        meta = locales[code]
        out.append(
            '    %s: {"name": %s, "english_name": %s, "flag": %s, "dir": %s, '
            '"review": %s},' % (
                py(code),
                py(meta["name"]),
                py(meta["english_name"]),
                py(meta["flag"]),
                py(meta["dir"]),
                py(meta["review"]),
            ))
    out.append("}")
    out.append("")
    out.append("WEB_CATALOGUES = {")
    for code in codes:
        out.append("    %s: {" % py(code))
        for key in catalogues["en"]:
            # Same reason as the metadata above: a translator who reaches for
            # an emoji puts an astral character in a catalogue, and json.dumps
            # would write it as a surrogate pair that Python source cannot mean.
            out.append("        %s: %s," % (
                py(key), py(catalogues[code][key])))
        out.append("    },")
    out.append("}")
    out.append(END)
    region = "\n".join(out) + "\n"

    # Read back what was just written and compare it to what went in. The
    # region is source code generated from data, and every way that goes wrong
    # is silent at this point and loud somewhere else: the surrogate-pair bug
    # produced a file that imported perfectly and raised on the first page that
    # rendered a picker. Parsing is cheap and the failure it catches is not.
    parsed = {}
    for node in ast.parse(region.replace(BEGIN, "").replace(END, "")).body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            parsed[node.targets[0].id] = ast.literal_eval(node.value)
    if parsed.get("WEB_LOCALES") != locales:
        sys.exit("the generated locale table does not read back as it was written")
    if parsed.get("WEB_CATALOGUES") != catalogues:
        sys.exit("the generated catalogues do not read back as they were written")
    return region


def main():
    check = "--check" in sys.argv[1:]
    codes, locales, catalogues = load()
    region = render(codes, locales, catalogues)
    if "--validate" in sys.argv[1:]:
        # Everything above this line is the reading and the checking; nothing
        # below it decides whether a catalogue is acceptable. Stopping here
        # exercises the refusals without writing to the tree.
        print("locales/ validated: %d languages, %d keys each."
              % (len(codes), len(catalogues["en"])))
        return

    with io.open(TARGET, encoding="utf-8") as handle:
        source = handle.read()
    start = source.find(BEGIN)
    stop = source.find(END)
    if start < 0 or stop < 0:
        sys.exit("the generated locale region is missing from %s"
                 % os.path.relpath(TARGET, ROOT))
    stop = source.index("\n", stop) + 1
    updated = source[:start] + region + source[stop:]

    if check:
        if updated != source:
            sys.exit("src/spm_web_server.py is stale: locales/*.json changed. "
                     "Run tools/build-locales.py.")
        print("locale region is current with locales/ (%d languages, %d keys)."
              % (len(codes), len(catalogues["en"])))
        return
    if updated != source:
        with io.open(TARGET, "w", encoding="utf-8") as handle:
            handle.write(updated)
    print("Folded %d languages (%d keys each) into src/spm_web_server.py."
          % (len(codes), len(catalogues["en"])))


if __name__ == "__main__":
    main()
