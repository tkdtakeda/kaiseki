using System;
using System.Collections.Generic;
using System.IO;
using FolderScan.Analysis;
using FolderScan.Core;
using FolderScan.Gaps;

namespace FolderScan.Diag {
    // Something this scan did not examine, and what would let the next scan examine it.
    public sealed class CoverageItem {
        public string Kind, Detail, Next;
        public int Count;
    }

    public static class CoverageDiag {
        // code-like extensions that no detector understands yet
        static readonly HashSet<string> Unsupported = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            ".php", ".go", ".rb", ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".swift", ".sh", ".bash", ".pl", ".pm", ".lua", ".r", ".scala", ".m", ".dart",
            ".ex", ".exs", ".erl", ".clj", ".groovy", ".f90", ".for", ".asm", ".cob", ".cbl", ".pas", ".tcl", ".awk", ".sed", ".mk", ".gradle", ".jsp", ".asp", ".aspx", ".cshtml", ".razor", ".svelte" };
        static readonly HashSet<string> ConfigNotJson = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".ini", ".cfg", ".conf", ".yaml", ".yml", ".toml", ".xml", ".config", ".properties", ".env" };

        static void Add(List<CoverageItem> l, string kind, int count, string detail, string next) {
            if (count <= 0) return;
            CoverageItem c = new CoverageItem(); c.Kind = kind; c.Count = count; c.Detail = detail; c.Next = next; l.Add(c);
        }

        static string ExtSummary(Dictionary<string, int> d) {
            List<KeyValuePair<string, int>> l = new List<KeyValuePair<string, int>>(d);
            l.Sort(delegate (KeyValuePair<string, int> a, KeyValuePair<string, int> b) { int r = b.Value.CompareTo(a.Value); return r != 0 ? r : string.CompareOrdinal(a.Key, b.Key); });
            List<string> s = new List<string>(); foreach (KeyValuePair<string, int> kv in l) s.Add(kv.Key + " x" + kv.Value);
            return string.Join(" ", s.ToArray());
        }

        static void Inc(Dictionary<string, int> d, string k) { int v; d.TryGetValue(k, out v); d[k] = v + 1; }

        public static List<CoverageItem> Run(ScanContext c) {
            LinkState k = c.Link; Settings s = c.Settings;
            List<CoverageItem> l = new List<CoverageItem>();
            Add(l, "folder-access-error", c.ScanErrors.Count, c.ScanErrors.Count > 0 ? c.ScanErrors[0].Target + " : " + c.ScanErrors[0].Message : "", "run with an account that can read these folders, or scan them separately");
            Dictionary<string, int> unsup = new Dictionary<string, int>(), skipped = new Dictionary<string, int>(), cfg = new Dictionary<string, int>();
            int readErr = 0, truncated = 0, tmo = 0;
            foreach (FileEntry x in k.Fx) {
                string ext = x.Ext.Length == 0 ? "(none)" : x.Ext;
                if (x.Kind == "error") readErr++;
                if (x.Kind == "skipped") Inc(skipped, ext);
                if (x.Lang.Length == 0 && Unsupported.Contains(x.Ext)) Inc(unsup, ext);
                if (x.Kind == "text" && ConfigNotJson.Contains(x.Ext)) Inc(cfg, ext);
                if (s.LinkMaxMb > 0 && x.File.Length > s.LinkMaxBytes && (x.Kind == "text" || x.Kind == "binary")) truncated++;
                SemItem sm; if (k.Sem.TryGetValue(x.No, out sm) && !string.IsNullOrEmpty(sm.Tmo)) tmo++;
            }
            int nUnsup = 0; foreach (int v in unsup.Values) nUnsup += v;
            // read depth : files read only by the generic layer, by extension (= candidates for a new detector)
            Dictionary<string, int> genOnly = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int nStruct = 0, nGen = 0, nNone = 0;
            foreach (FileEntry x in k.Fx) {
                if (x.Depth == "structure") nStruct++;
                else if (x.Depth == "generic") { nGen++; Inc(genOnly, (x.Ext.Length == 0 ? "(none)" : x.Ext) + " " + x.Kind); }
                else nNone++;
            }
            List<KeyValuePair<string, int>> gl = new List<KeyValuePair<string, int>>(genOnly);
            gl.Sort(delegate (KeyValuePair<string, int> a, KeyValuePair<string, int> b) { int r = b.Value.CompareTo(a.Value); return r != 0 ? r : string.CompareOrdinal(a.Key, b.Key); });
            Dictionary<string, int> top5 = new Dictionary<string, int>();
            for (int i = 0; i < gl.Count && i < 5; i++) top5[gl[i].Key] = gl[i].Value;
            Add(l, "read-depth-generic-only", nGen, "structure " + nStruct + " / generic only " + nGen + " / not read " + nNone + " ; most common generic-only : " + ExtSummary(top5),
                "only strings were read from these files : a detector for the most common format (first in the list) would add structure (calls, keys, records)");
            Add(l, "unsupported-language", nUnsup, ExtSummary(unsup), "these files are listed but their imports / calls are not analyzed : a detector for the language is needed");
            int nCfg = 0; foreach (int v in cfg.Values) nCfg += v;
            Add(l, "config-format-not-analyzed", nCfg, ExtSummary(cfg), "only json keys are analyzed in [16-4] : an ini / yaml / xml key reader would link these settings to code");
            int nSkip = 0; foreach (int v in skipped.Values) nSkip += v;
            Add(l, "content-skipped", nSkip, ExtSummary(skipped), "SKIPEXT : content of these extensions is not read (media / archive)");
            Add(l, "read-error", readErr, "", "files could not be opened (locked or no permission)");
            Add(l, "regex-timeout", tmo, "", "some lines were not analyzed by some rules : see [19] regex-timeout");
            Add(l, "read-limit", truncated, "LINKMAXMB=" + s.LinkMaxMb, "raise LINKMAXMB (0 = whole file) if memory allows");
            int cabs = 0; foreach (FileInfo f in c.AllFiles) if (string.Equals(f.Extension, ".cab", StringComparison.OrdinalIgnoreCase)) cabs++;
            Add(l, "cab-not-extracted", cabs - c.CabMap.Count, "CABEXT=" + s.CabExt + " per folder", "raise CABEXT to analyze the contents of more cab files");
            if (s.DatMaxMb > 0) {
                int big = 0; foreach (FileInfo f in c.AllFiles) if (string.Equals(f.Extension, ".dat", StringComparison.OrdinalIgnoreCase) && f.Length > s.DatMaxBytes) big++;
                Add(l, "dat-dump-limit", big, "DATMAXMB=" + s.DatMaxMb, "raise DATMAXMB (0 = whole file) to dump these .dat files fully");
            }
            int unprobed = 0, unparsed = 0;
            foreach (Gap g in c.Gaps) { if (!g.Probed) unprobed++; if (g.Kind == "format-not-parsed" && g.Explained.Length == 0) unparsed++; }
            Add(l, "gap-not-probed", unprobed, "GAPMAX=" + s.GapMax + " per kind", "raise GAPMAX to collect probe evidence for every gap");
            Add(l, "format-not-parsed", unparsed, "", "binary / text formats no parser understood : see [19] format-not-parsed (header and strings are shown)");
            return l;
        }
    }
}
