using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Security.Cryptography;

// Content units, explicit references, key values, delimited / fixed-width structure.
// Ported verbatim from folderscan v5.18 (embedded Add-Type helper).
namespace FolderScan.Analysis {
public class Unit { public string Loc; public string Text; }
public class RefAgg { public string Ids; public int Count; public List<string> Locs = new List<string>(); public string Ctx; }
public class TableInfo { public string Info = ""; public List<string[]> Cols = new List<string[]>(); }
public class RecSet { public int Len; public double Ratio; public long Total; public List<byte[]> Recs = new List<byte[]>(); }
public class Field { public int Start; public int Len; public string Cls; public int Distinct; public string Ex; }
public static class LinkTool {
    static FileStream Open(string p) {
        return new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536);
    }
    static int ReadFull(Stream s, byte[] b, int len) {
        int t = 0;
        while (t < len) { int r = s.Read(b, t, len - t); if (r <= 0) break; t += r; }
        return t;
    }
    public static string Clean(string s) {
        if (s == null) return "";
        return s.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
    }
    public static string Sha(string p) {
        using (SHA256 sha = SHA256.Create())
        using (FileStream fs = Open(p)) { return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", ""); }
    }
    public static bool IsText(string p) {
        byte[] b = new byte[8192]; int n;
        using (FileStream fs = Open(p)) { n = ReadFull(fs, b, b.Length); }
        if (n == 0) return false;
        if (n >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF))) return true;
        int pr = 0, z = 0;
        for (int i = 0; i < n; i++) { byte v = b[i]; if (v == 0) z++; else if (v == 9 || v == 10 || v == 13 || v >= 32) pr++; }
        return z == 0 && pr >= n * 0.95;
    }
    // text  : one unit per line (Loc = L<line>)
    // binary: one unit per printable ASCII run (Loc = 0x<offset>)
    public static List<Unit> Units(string p, bool text, int cp, long maxBytes, int minLen) {
        List<Unit> u = new List<Unit>();
        if (text) {
            using (StreamReader sr = new StreamReader(Open(p), Encoding.GetEncoding(cp), true)) {
                string line; long ln = 0; long read = 0;
                while ((line = sr.ReadLine()) != null) {
                    ln++; read += line.Length + 1;
                    Unit x = new Unit(); x.Loc = "L" + ln; x.Text = line; u.Add(x);
                    if (maxBytes > 0 && read >= maxBytes) break;
                }
            }
        } else {
            using (FileStream fs = Open(p)) {
                byte[] buf = new byte[1048576]; int r; long off = 0; long start = -1;
                StringBuilder sb = new StringBuilder();
                while ((r = ReadFull(fs, buf, buf.Length)) > 0) {
                    for (int i = 0; i < r; i++) {
                        byte v = buf[i];
                        if (v >= 32 && v < 127) { if (start < 0) start = off + i; sb.Append((char)v); }
                        else { Flush(u, sb, start, minLen); start = -1; }
                    }
                    off += r;
                    if (maxBytes > 0 && off >= maxBytes) break;
                    if (r < buf.Length) break;
                }
                Flush(u, sb, start, minLen);
            }
        }
        return u;
    }
    static void Flush(List<Unit> u, StringBuilder sb, long start, int minLen) {
        if (sb.Length >= minLen && start >= 0) {
            Unit x = new Unit(); x.Loc = "0x" + start.ToString("X8"); x.Text = sb.ToString(); u.Add(x);
        }
        sb.Length = 0;
    }
    public static void WriteUnits(List<Unit> u, TextWriter w) {
        foreach (Unit x in u) { w.Write(x.Loc.PadLeft(10)); w.Write(": "); w.WriteLine(x.Text); }
    }
    // ---------- explicit references : file names written inside the file ----------
    static readonly char[] SEP = new char[] { ' ', '\t', '"', '\'', '\\', '/', ',', ';', '=', '<', '>', '(', ')', '[', ']', '{', '}', '|', ':', '*', '?', '&', '+', '`', '#', '@', '!' };
    public static List<string[]> Refs(List<Unit> u, Dictionary<string, string> names, string self) {
        Dictionary<string, RefAgg> agg = new Dictionary<string, RefAgg>();
        List<string> order = new List<string>();
        foreach (Unit x in u) {
            string[] tk = x.Text.ToLowerInvariant().Split(SEP, StringSplitOptions.RemoveEmptyEntries);
            foreach (string t0 in tk) {
                string t = t0.TrimEnd('.');
                if (t.Length == 0 || t == self) continue;
                string ids;
                if (!names.TryGetValue(t, out ids)) continue;
                RefAgg a;
                if (!agg.TryGetValue(t, out a)) {
                    a = new RefAgg(); a.Ids = ids;
                    string c = Clean(x.Text).Trim(); if (c.Length > 160) c = c.Substring(0, 160) + "..";
                    a.Ctx = c; agg[t] = a; order.Add(t);
                }
                a.Count++;
                if (a.Locs.Count < 3 && !a.Locs.Contains(x.Loc)) a.Locs.Add(x.Loc);
            }
        }
        List<string[]> rows = new List<string[]>();
        foreach (string t in order) {
            RefAgg a = agg[t];
            rows.Add(new string[] { t, a.Ids, a.Count.ToString(), string.Join(" ", a.Locs.ToArray()), a.Ctx });
        }
        return rows;
    }
    // ---------- candidate key values (lot No., order No., date, code ...) ----------
    public static HashSet<string> Keys(List<Unit> u, int maxKeys) {
        HashSet<string> h = new HashSet<string>(StringComparer.Ordinal);
        StringBuilder sb = new StringBuilder();
        foreach (Unit x in u) {
            string s = x.Text;
            for (int i = 0; i <= s.Length; i++) {
                char c = i < s.Length ? s[i] : ' ';
                bool w = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-' || c == '_';
                if (w) sb.Append(c);
                else { AddKey(h, sb); sb.Length = 0; if (h.Count >= maxKeys) return h; }
            }
        }
        return h;
    }
    static void AddKey(HashSet<string> h, StringBuilder sb) {
        int n = sb.Length; if (n < 6 || n > 32) return;
        int d = 0; bool same = true;
        for (int i = 0; i < n; i++) { if (sb[i] >= '0' && sb[i] <= '9') d++; if (sb[i] != sb[0]) same = false; }
        if (d == 0 || same) return;
        h.Add(sb.ToString().ToUpperInvariant());
    }
    public static void FieldKeys(List<byte[]> recs, List<Field> fs, int cp, HashSet<string> keys, int maxKeys) {
        Encoding e = Encoding.GetEncoding(cp);
        StringBuilder sb = new StringBuilder();
        foreach (Field f in fs) {
            if (f.Cls != "NUM" && f.Cls != "TEXT") continue;
            foreach (byte[] r in recs) {
                if (keys.Count >= maxKeys) return;
                string v = e.GetString(r, f.Start, f.Len).Trim();
                if (v.IndexOf(' ') >= 0) continue;
                sb.Length = 0; sb.Append(v); AddKey(keys, sb);
            }
        }
    }
    // ---------- delimited text (CSV / TSV ...) ----------
    public static TableInfo Delim(List<Unit> u, int maxLines) {
        TableInfo t = new TableInfo();
        char[] ds = new char[] { ',', '\t', ';', '|' };
        string[] dn = new string[] { "COMMA", "TAB", "SEMICOLON", "PIPE" };
        List<string> lines = new List<string>();
        foreach (Unit x in u) { if (x.Text.Trim().Length > 0) lines.Add(x.Text); if (lines.Count >= maxLines) break; }
        if (lines.Count < 2) return t;
        int best = -1; int bestMode = 0; double bestRatio = 0;
        for (int d = 0; d < ds.Length; d++) {
            Dictionary<int, int> h = new Dictionary<int, int>();
            foreach (string s in lines) { int c = 0; foreach (char ch in s) if (ch == ds[d]) c++; int v; h.TryGetValue(c, out v); h[c] = v + 1; }
            int mode = 0, mc = 0;
            foreach (KeyValuePair<int, int> kv in h) if (kv.Value > mc || (kv.Value == mc && kv.Key > mode)) { mode = kv.Key; mc = kv.Value; }
            double ratio = (double)mc / lines.Count;
            if (mode > 0 && ratio >= 0.9 && (ratio > bestRatio || (ratio == bestRatio && mode > bestMode))) { best = d; bestMode = mode; bestRatio = ratio; }
        }
        if (best < 0) return t;
        int nc = bestMode + 1;
        t.Info = "delimiter=" + dn[best] + "  columns=" + nc + "  consistency=" + (bestRatio * 100).ToString("0.0") + "%  lines checked=" + lines.Count + "  (row 1 = header candidate, quotes not parsed)";
        string[] head = lines[0].Split(ds[best]);
        for (int c = 0; c < nc; c++) {
            int num = 0, n = 0; HashSet<string> dist = new HashSet<string>(); List<string> ex = new List<string>();
            for (int i = 1; i < lines.Count; i++) {
                string[] p = lines[i].Split(ds[best]); if (p.Length != nc) continue;
                string v = p[c].Trim().Trim('"'); n++;
                double dd; if (v.Length > 0 && double.TryParse(v, out dd)) num++;
                if (dist.Count < 100000) dist.Add(v);
                if (ex.Count < 3 && !ex.Contains(v)) ex.Add(v);
            }
            t.Cols.Add(new string[] { (c + 1).ToString(), Clean(c < head.Length ? head[c].Trim() : ""), n > 0 ? (100.0 * num / n).ToString("0") : "-", dist.Count.ToString(), Clean(string.Join(" | ", ex.ToArray())) });
        }
        return t;
    }
    // ---------- fixed-width records ----------
    public static RecSet LineRecs(List<Unit> u, int cp, int maxRec) {
        Encoding e = Encoding.GetEncoding(cp);
        List<byte[]> all = new List<byte[]>();
        foreach (Unit x in u) { all.Add(e.GetBytes(x.Text)); if (all.Count >= maxRec) break; }
        RecSet s = new RecSet(); s.Total = u.Count;
        if (all.Count < 3) return s;
        Dictionary<int, int> h = new Dictionary<int, int>();
        foreach (byte[] b in all) { int v; h.TryGetValue(b.Length, out v); h[b.Length] = v + 1; }
        int mode = 0, mc = 0;
        foreach (KeyValuePair<int, int> kv in h) if (kv.Value > mc) { mode = kv.Key; mc = kv.Value; }
        s.Len = mode; s.Ratio = 100.0 * mc / all.Count;
        if (s.Ratio >= 90 && mode >= 4) foreach (byte[] b in all) if (b.Length == mode) s.Recs.Add(b);
        return s;
    }
    public static RecSet FixedRecs(string p, int len, int maxRec) {
        RecSet s = new RecSet(); s.Len = len; s.Ratio = 100;
        if (len < 4) return s;
        using (FileStream fs = Open(p)) {
            s.Total = fs.Length / len;
            byte[] b = new byte[len];
            while (s.Recs.Count < maxRec) { int r = ReadFull(fs, b, len); if (r < len) break; s.Recs.Add((byte[])b.Clone()); }
        }
        return s;
    }
    public static List<Field> Profile(List<byte[]> recs, int cp) {
        List<Field> fs = new List<Field>();
        if (recs.Count < 2) return fs;
        int R = recs[0].Length; int N = recs.Count;
        string[] cls = new string[R];
        for (int k = 0; k < R; k++) {
            byte f = recs[0][k]; bool cst = true; int dg = 0, pr = 0, hi = 0;
            foreach (byte[] r in recs) {
                byte v = r[k];
                if (v != f) cst = false;
                if ((v >= 48 && v <= 57) || v == 32 || v == 46 || v == 45 || v == 43) dg++;
                if (v >= 32 && v < 127) pr++; else if (v >= 128) hi++;
            }
            if (cst) cls[k] = (f >= 32 && f < 127) ? "CONST" : "CONSTB";
            else if (dg >= N * 0.98) cls[k] = "NUM";
            else if (pr >= N * 0.98) cls[k] = "TEXT";
            else if (pr + hi >= N * 0.98) cls[k] = "MBCS";
            else cls[k] = "BIN";
        }
        Encoding e = Encoding.GetEncoding(cp);
        int st = 0;
        for (int k = 1; k <= R; k++) {
            if (k == R || cls[k] != cls[st]) {
                Field fd = new Field(); fd.Start = st; fd.Len = k - st; fd.Cls = cls[st];
                HashSet<string> d = new HashSet<string>(); List<string> ex = new List<string>();
                foreach (byte[] r in recs) {
                    string v = Val(r, fd, e);
                    if (d.Count < 100000) d.Add(v);
                    if (ex.Count < 3 && !ex.Contains(v)) ex.Add(v);
                }
                fd.Distinct = d.Count; fd.Ex = Clean(string.Join(" | ", ex.ToArray()));
                fs.Add(fd); st = k;
            }
        }
        return fs;
    }
    static string Val(byte[] r, Field f, Encoding e) {
        if (f.Cls == "BIN" || f.Cls == "CONSTB") {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < f.Len && i < 32; i++) sb.Append(r[f.Start + i].ToString("X2"));
            if (f.Len > 32) sb.Append("..");
            if (f.Len == 2) sb.Append(" (LE=").Append(BitConverter.ToUInt16(r, f.Start)).Append(")");
            else if (f.Len == 4) sb.Append(" (LE=").Append(BitConverter.ToUInt32(r, f.Start)).Append(")");
            else if (f.Len == 8) sb.Append(" (LE=").Append(BitConverter.ToInt64(r, f.Start)).Append(")");
            return sb.ToString();
        }
        return "[" + e.GetString(r, f.Start, f.Len) + "]";
    }
    public static List<string[]> FieldRows(List<Field> fs) {
        List<string[]> rows = new List<string[]>();
        foreach (Field f in fs) rows.Add(new string[] { f.Start.ToString(), f.Len.ToString(), f.Cls, f.Distinct.ToString(), f.Ex });
        return rows;
    }
}
}
