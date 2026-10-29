folderscan v6.1 change set

Replace:
- Findings.cs            <- Findings_v6.1.cs (rename to Findings.cs)
- ScanContext.cs         <- ScanContext_v6.1.cs (rename to ScanContext.cs)

Add:
- TokenProvenance.cs

Then modify TokenSymbolSections.cs at the point immediately before each unresolved EXTFILE edge is added.
The complete replacement expression is:

    string provenanceReason;
    bool promote = TokenProvenance.ShouldCreateExternalEdge(x, tok, leaf, ctxS, best, out provenanceReason);
    if (promote) {
        E.Add("EXTFILE", self, "", tok + " [" + best + "]", r[2], ev0);
    }

For wildcard tokens, keep the current external-pattern behavior because the wildcard itself is explicit file-pattern evidence.
For non-wildcard tokens, use the block above instead of the current unconditional EXTFILE Add.
Do not remove the row from file_tokens TSV. This preserves extracted evidence while preventing weak HTML/Jinja bare words from becoming actionable findings.

Expected checks after rebuild:
1. Same finding ID appears only once in latest_diag.json.
2. sqlite_master/sqlite_schema are class=system-object, action=benign.
3. templates/index.html bare words such as join, now, rne, rne_ctime, rne_mtime, text remain visible in file_tokens but do not become EXTFILE findings.
4. Real asset names with an extension/path and wildcard patterns remain analyzed.
