#!/usr/bin/env python3
"""A reference SPM plugin.

It shows the whole plugin contract in one small program. On stdin it receives a
JSON context the trusted host built from its granted capabilities:

    {
      "caps": ["records.list", ...],   # what this run was granted
      "records": [{"id","label","username","url"}, ...],  # only with records.list
      "generated": "..."               # only with password.generate
    }

Record summaries carry labels, usernames and URLs -- never a password. A plugin
never sees the vault key, and reaches a secret only through the `secret.get`
capability, which delivers the records of one named scope as SPM_SECRET_<VAR>
environment variables (this example does not ask for that).

A plugin's own stdout is shown to the user. To ask the host for a side effect it
was granted -- copying to the clipboard, sending a notification -- it writes a
small JSON document to the file named by $SPM_PLUGIN_RESULT; the host performs
only the effects whose capability was granted. This example needs neither.
"""
import json
import os
import sys


def main():
    try:
        ctx = json.load(sys.stdin)
    except Exception:
        ctx = {}
    records = ctx.get("records", [])
    print("SPM inventory: %d account(s)" % len(records))
    without_url = []
    for record in records:
        label = record.get("label", "")
        url = record.get("url", "")
        print("  - %-28s %s" % (label, url or "(no url)"))
        if not url:
            without_url.append(label)
    if without_url:
        print("Without a URL (the extension cannot match these): %s"
              % ", ".join(without_url))
    # Nothing to hand back to the host: no clipboard, no notification. A plugin
    # that wanted one would write it to os.environ["SPM_PLUGIN_RESULT"].
    _ = os.environ.get("SPM_PLUGIN_RESULT")


if __name__ == "__main__":
    main()
