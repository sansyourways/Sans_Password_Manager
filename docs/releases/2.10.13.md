# SPM 2.10.13

Adds the diagnostic half of the 2.10.12 line-break fix.

## Why

2.10.12 stopped SPM writing vault fields containing characters that Python's
`str.splitlines()` treats as line breaks. It could not do anything about records
already written that way, and those records are genuinely hard to notice: the
entry still lists correctly in the CLI, because Bash reads the vault with
`read -r` and splits on newline alone, while Web Mode reads it with
`splitlines()`, sees two fragments where one record should be, finds neither has
enough fields, and shows nothing. An entry that is present in one client and
absent in the other looks like a sync bug, not corruption.

## What was added

`spm doctor` now scans for those records and reports them.

```
[!] 1 record(s) contain a line-break character; 0 leftover fragment(s):
      line 3     PASSWORD      id=2     My␣Bank            U+2028 LINE SEPARATOR
    These entries are invisible in Web Mode. The vault was NOT changed.
    Repair by re-saving each one from the CLI (spm edit <id>), which
    rewrites the field through the 2.10.12 sanitiser.
```

It reports the record type, id, label and the offending character by Unicode
name. Leftover fragments from an already-split record are counted separately.

## What it will not do

**The scan never modifies the vault.** Repair is manual and deliberate:
re-save the named entry from the CLI so the field passes through the current
sanitiser. Automatic repair was not implemented — rewriting records in a live
vault is not something a diagnostic should do on your behalf.

Three properties are asserted by regression, not just intended:

- the secret field is never printed, for any record shape
- a break character inside a label renders as a visible blank (`␣`), never the
  raw character, so the report itself cannot be split or spoofed
- the vault is byte-identical afterwards

## Verification

`bash -n`, `shellcheck -x -S warning` and `git diff --check` clean; full
regression suite green. The new assertions were each confirmed to fail when
their fix is inverted, so none are silently skipped. Exercised end to end
against a throwaway vault seeded with `U+2028`, `U+000B`, `U+2029` and `U+0085`
records plus one orphan fragment — all five found, clean records untouched, and
a clean vault correctly reports nothing.
