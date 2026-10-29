using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Security.Cryptography;

// Index of key values shared between files.
// Ported verbatim from folderscan v5.18 (embedded Add-Type helper).
namespace FolderScan.Analysis {
public class KeyIndex {
    Dictionary<string, List<int>> map = new Dictionary<string, List<int>>(StringComparer.Ordinal);
    public int KeyCount { get { return map.Count; } }
    public void Add(int no, HashSet<string> keys) {
        foreach (string k in keys) {
            List<int> l;
            if (!map.TryGetValue(k, out l)) { l = new List<int>(); map[k] = l; }
            if (l.Count == 0 || l[l.Count - 1] != no) l.Add(no);
        }
    }
    public List<string[]> Pairs(int maxFiles, int nEx) {
        Dictionary<long, int> cnt = new Dictionary<long, int>();
        Dictionary<long, List<string>> ex = new Dictionary<long, List<string>>();
        foreach (KeyValuePair<string, List<int>> kv in map) {
            List<int> l = kv.Value;
            if (l.Count < 2 || l.Count > maxFiles) continue;
            for (int i = 0; i < l.Count; i++) for (int j = i + 1; j < l.Count; j++) {
                long pk = ((long)l[i] << 32) | (uint)l[j];
                int c; cnt.TryGetValue(pk, out c); cnt[pk] = c + 1;
                List<string> e; if (!ex.TryGetValue(pk, out e)) { e = new List<string>(); ex[pk] = e; }
                if (e.Count < nEx) e.Add(kv.Key);
            }
        }
        List<string[]> rows = new List<string[]>();
        foreach (KeyValuePair<long, int> kv in cnt)
            rows.Add(new string[] { (kv.Key >> 32).ToString(), (kv.Key & 0xFFFFFFFFL).ToString(), kv.Value.ToString(), string.Join(" ", ex[kv.Key].ToArray()) });
        rows.Sort(delegate (string[] a, string[] b) { return int.Parse(b[2]).CompareTo(int.Parse(a[2])); });
        return rows;
    }
    public List<string[]> Common(int top) {
        List<KeyValuePair<string, List<int>>> l = new List<KeyValuePair<string, List<int>>>();
        foreach (KeyValuePair<string, List<int>> kv in map) if (kv.Value.Count >= 2) l.Add(kv);
        l.Sort(delegate (KeyValuePair<string, List<int>> a, KeyValuePair<string, List<int>> b) { return b.Value.Count.CompareTo(a.Value.Count); });
        List<string[]> rows = new List<string[]>();
        for (int i = 0; i < Math.Min(top, l.Count); i++) {
            List<string> ids = new List<string>();
            for (int j = 0; j < Math.Min(30, l[i].Value.Count); j++) ids.Add(l[i].Value[j].ToString());
            if (l[i].Value.Count > 30) ids.Add("..");
            rows.Add(new string[] { l[i].Key, l[i].Value.Count.ToString(), string.Join(",", ids.ToArray()) });
        }
        return rows;
    }
}
}
