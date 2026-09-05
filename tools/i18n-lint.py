#!/usr/bin/env python3
"""Check every locales/*.json before it reaches the dashboard.

Run this after editing a catalogue and before opening a pull request:

    python3 tools/i18n-lint.py

It is the same check the regression suite runs, so a clean run here means the
suite will not be the first thing to tell you something is wrong.
"""

import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# A directory may be named on the command line, which is how the regression
# suite feeds this a deliberately broken catalogue and checks that it refuses.
# A check nothing ever fails is a check nobody has run.
LOCALE_DIR = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "locales")

# A catalogue value is inserted as textContent, never as markup, so a tag in a
# value cannot execute -- it just renders as literal angle brackets and looks
# broken. `</script>` is the one that would matter if a value ever reached a
# <script> element, and the dashboard escapes for that too. Refusing both here
# means neither defence is load-bearing on its own.
MARKUP = re.compile(r"<\s*/?\s*[a-zA-Z]")
PLACEHOLDER = re.compile(r"\{[a-z_][a-z0-9_]*\}")


def fail(problems):
    for problem in problems:
        sys.stderr.write("  %s\n" % problem)
    sys.stderr.write("%d problem(s).\n" % len(problems))
    sys.exit(1)


def main():
    problems = []
    codes = sorted(
        name[:-5] for name in os.listdir(LOCALE_DIR) if name.endswith(".json"))
    if "en" not in codes:
        fail(["en.json is missing from %s; it defines the key set" % LOCALE_DIR])

    catalogues, metas = {}, {}
    for code in codes:
        path = os.path.join(LOCALE_DIR, "%s.json" % code)
        try:
            doc = json.load(io.open(path, encoding="utf-8"))
        except ValueError as exc:
            problems.append("%s.json is not valid JSON: %s" % (code, exc))
            continue
        metas[code] = doc.get("meta") or {}
        catalogues[code] = doc.get("strings") or {}
        flag = metas[code].get("flag") or ""
        # Two regional indicator symbols and nothing else. A stray emoji or a
        # bare two-letter string renders as text in the middle of the picker,
        # which looks like a defect rather than like a missing flag.
        if len(flag) != 2 or any(not 0x1F1E6 <= ord(ch) <= 0x1F1FF for ch in flag):
            problems.append(
                "%s.json declares flag %r; expected two regional indicator symbols"
                % (code, flag))
        if metas[code].get("code") != code:
            problems.append(
                "%s.json declares code %r, which does not match its filename"
                % (code, metas[code].get("code")))
        # Lowercase, because the dashboard lowercases whatever the cookie or
        # the query string carries before matching it.
        if code != code.lower():
            problems.append("%s.json: language codes must be lowercase" % code)

    english = catalogues.get("en", {})
    for code in sorted(catalogues):
        strings = catalogues[code]
        absent = sorted(set(english) - set(strings))
        extra = sorted(set(strings) - set(english))
        if absent:
            problems.append("%s is missing %d key(s): %s%s" % (
                code, len(absent), ", ".join(absent[:5]),
                "..." if len(absent) > 5 else ""))
        if extra:
            problems.append("%s has %d key(s) English does not: %s%s" % (
                code, len(extra), ", ".join(extra[:5]),
                "..." if len(extra) > 5 else ""))
        for key in sorted(set(strings) & set(english)):
            value = strings[key]
            if not isinstance(value, str):
                problems.append("%s: %s is not a string" % (code, key))
                continue
            if MARKUP.search(value):
                problems.append(
                    "%s: %s contains markup; values are inserted as text"
                    % (code, key))
            if "</script" in value.lower():
                problems.append("%s: %s contains a script terminator"
                                % (code, key))
            # A translation that drops {n} silently loses the number it was
            # meant to show, and one that invents a placeholder renders the
            # braces literally. Both look like a typo and neither raises.
            if set(PLACEHOLDER.findall(value)) != set(
                    PLACEHOLDER.findall(english[key])):
                problems.append(
                    "%s: %s does not use the same placeholders as English (%s)"
                    % (code, key,
                       ", ".join(sorted(PLACEHOLDER.findall(english[key])))
                       or "none"))

    if problems:
        fail(problems)
    reviewed = sum(1 for code in metas if metas[code].get("review") == "maintained")
    print("i18n: %d languages, %d keys each, %d maintained, %d unreviewed, "
          "%d flagged."
          % (len(catalogues), len(english), reviewed,
             len(catalogues) - reviewed,
             sum(1 for code in metas if metas[code].get("flag"))))


if __name__ == "__main__":
    main()
