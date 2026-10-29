folderscan v6.1 change set  (applied)

Applied in src/:
- src/Diag/Findings.cs           v6.1 (duplicate finding IDs merged, SQLite system objects are benign)
- src/Core/ScanContext.cs        v6.1
- src/Sections/TokenProvenance.cs           new
- src/Sections/TokenSymbolSections.cs       EXTFILE edges go through TokenProvenance

TokenSymbolSections.cs : before each unresolved non-wildcard EXTFILE edge is added,

    string provenanceReason;
    bool promote = TokenProvenance.ShouldCreateExternalEdge(x, tok, leaf, ctxS, best, out provenanceReason);
    if (promote) {
        E.Add("EXTFILE", self, "", tok + " [" + best + "]", r[2], ev0);
    }

Wildcard tokens keep the external-pattern behavior (the wildcard itself is file-pattern evidence).
The row stays in the file_tokens TSV, so extracted evidence is kept; weak HTML/Jinja bare words
just do not become actionable findings (Status column shows "suppressed(<reason>)").

Fix found while applying:
- Findings.cs : SQL details look like "table sqlite_master", so the kind word is removed
  before the system-object check. Without it sqlite_master stayed "actionable".

Checks (all verified after the rebuild):
1. Same finding ID appears only once in latest_diag.json.
2. sqlite_master/sqlite_schema are class=system-object, action=benign.
3. templates/index.html bare words such as join, now, rne, rne_ctime, rne_mtime, text do not
   become EXTFILE findings.
4. Real asset names with an extension/path and wildcard patterns remain analyzed.
