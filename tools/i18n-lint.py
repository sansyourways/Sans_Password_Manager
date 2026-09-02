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
LOCALE_DIR = os.path.join(ROOT, "locales")

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
        fail(["locales/en.json is missing; it defines the key set"])

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
    print("i18n: %d languages, %d keys each, %d maintained, %d unreviewed."
          % (len(catalogues), len(english), reviewed, len(catalogues) - reviewed))


if __name__ == "__main__":
    main()
