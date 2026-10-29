using System.Collections;
using System.Collections.Generic;
using FolderScan.Analysis;

namespace FolderScan.Core {
    // Results of [18], used by the gap probe [19].
    public sealed class ReconState {
        public ExternalClassifier Ext;
        public readonly List<string[]> Resolved = new List<string[]>();       // resolved_relations rows
        public readonly SortedCounts StatusCount = new SortedCounts();       // [18-1] status -> pairs
        public readonly List<string[]> Conflicts = new List<string[]>();
        public readonly List<string[]> FileRecon = new List<string[]>();
        public readonly List<string[]> FileClass = new List<string[]>();
        public readonly SortedCounts FileClassCount = new SortedCounts();
        public readonly List<string[]> Unresolved = new List<string[]>();
        public readonly SortedCounts ExtClassCount = new SortedCounts();
        public readonly List<string[]> ArchRows = new List<string[]>();
    }

    // name -> count, listed sorted by name (the "$h.Keys | Sort-Object" pattern of v5.18)
    public sealed class SortedCounts {
        readonly Dictionary<string, int> d = new Dictionary<string, int>(System.StringComparer.CurrentCultureIgnoreCase);
        public void Inc(string k) { int v; d.TryGetValue(k, out v); d[k] = v + 1; }
        public int Count { get { return d.Count; } }
        public int this[string k] { get { int v; d.TryGetValue(k, out v); return v; } }
        public List<string> SortedKeys() {
            List<string> l = new List<string>(d.Keys);
            FolderScan.Sections.SymbolUseSection.StableSort(l);
            return l;
        }
        public List<string[]> Rows() {
            List<string[]> r = new List<string[]>();
            foreach (string k in SortedKeys()) r.Add(new string[] { k, d[k].ToString() });
            return r;
        }
    }
}
