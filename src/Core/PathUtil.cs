using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace FolderScan.Core {
    public static class PathUtil {
        // Sort order of PowerShell Sort-Object for strings (culture aware, case-insensitive).
        public static readonly StringComparer SortCmp = StringComparer.Create(CultureInfo.CurrentCulture, true);
        // Grouping / lookup of paths (Windows paths are case-insensitive).
        public static readonly StringComparer KeyCmp = StringComparer.OrdinalIgnoreCase;

        // Path relative to root, "\" when equal (function Rel of v5.18).
        public static string Rel(string root, string p) {
            string r = p.Length >= root.Length ? p.Substring(root.Length) : p;
            return r.Length == 0 ? "\\" : r;
        }

        public static string TrimSep(string p) {
            return p.TrimEnd('\\', '/');
        }

        // Extension in lower case, "(none)" when there is none.
        public static string ExtOrNone(FileInfo f) {
            string x = f.Extension.ToLowerInvariant();
            return x.Length == 0 ? "(none)" : x;
        }

        public static string DirKey(FileInfo f) { return TrimSep(f.DirectoryName); }

        public static string Time(DateTime t) { return t.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture); }

        public static void SortByName(List<FileInfo> l) { l.Sort(delegate (FileInfo a, FileInfo b) { return SortCmp.Compare(a.Name, b.Name); }); }
        public static void SortByName(List<DirectoryInfo> l) { l.Sort(delegate (DirectoryInfo a, DirectoryInfo b) { return SortCmp.Compare(a.Name, b.Name); }); }
        public static void SortByFullName(List<FileInfo> l) { l.Sort(delegate (FileInfo a, FileInfo b) { return SortCmp.Compare(a.FullName, b.FullName); }); }
        public static void SortByFullName(List<DirectoryInfo> l) { l.Sort(delegate (DirectoryInfo a, DirectoryInfo b) { return SortCmp.Compare(a.FullName, b.FullName); }); }

        // Group-Object <key> | Sort-Object Name ; groups keep the input order of their items.
        public static List<KeyValuePair<string, List<T>>> GroupSorted<T>(IEnumerable<T> items, Func<T, string> key) {
            Dictionary<string, List<T>> d = new Dictionary<string, List<T>>(KeyCmp);
            List<string> order = new List<string>();
            foreach (T it in items) {
                string k = key(it);
                List<T> l;
                if (!d.TryGetValue(k, out l)) { l = new List<T>(); d[k] = l; order.Add(k); }
                l.Add(it);
            }
            order.Sort(SortCmp);
            List<KeyValuePair<string, List<T>>> r = new List<KeyValuePair<string, List<T>>>();
            foreach (string k in order) r.Add(new KeyValuePair<string, List<T>>(k, d[k]));
            return r;
        }
    }
}
