using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

// Binary analysis of .dat files : statistics, magic, record length, hex dump.
// Ported verbatim from folderscan v5.18 (embedded Add-Type helper).
namespace FolderScan.Analysis {
public class DatInfo {
    public long Size; public string Sha256; public double Printable; public double Zero; public double High;
    public double Entropy; public long LF; public long CR; public string Type; public string Magic;
    public string RecLen; public string HeadHex;
    public int BestLen; public double BestScore;
}
public static unsafe class DatTool {
    static string[] HX;
    static DatTool() { HX = new string[256]; for (int i = 0; i < 256; i++) HX[i] = i.ToString("X2"); }
    static int ReadFull(Stream s, byte[] b, int len) {
        int t = 0;
        while (t < len) { int r = s.Read(b, t, len - t); if (r <= 0) break; t += r; }
        return t;
    }
    static FileStream Open(string p) {
        return new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536);
    }
    static bool Sw(byte[] b, int n, params int[] m) {
        if (n < m.Length) return false;
        for (int i = 0; i < m.Length; i++) if (b[i] != m[i]) return false;
        return true;
    }
    static string Magic(byte[] b, int n) {
        if (Sw(b, n, 0x4D, 0x53, 0x43, 0x46)) return "CAB (MSCF)";
        if (Sw(b, n, 0x50, 0x4B, 0x03, 0x04)) return "ZIP";
        if (Sw(b, n, 0x1F, 0x8B)) return "GZIP";
        if (Sw(b, n, 0xFF, 0xD8, 0xFF)) return "JPEG";
        if (Sw(b, n, 0x89, 0x50, 0x4E, 0x47)) return "PNG";
        if (Sw(b, n, 0x49, 0x49, 0x2A, 0x00)) return "TIFF (LE)";
        if (Sw(b, n, 0x4D, 0x4D, 0x00, 0x2A)) return "TIFF (BE)";
        if (Sw(b, n, 0x42, 0x4D)) return "BMP?";
        if (Sw(b, n, 0x3C, 0x3F, 0x78, 0x6D, 0x6C)) return "XML";
        if (Sw(b, n, 0xEF, 0xBB, 0xBF)) return "UTF-8 BOM text";
        if (Sw(b, n, 0xFF, 0xFE)) return "UTF-16LE BOM";
        if (Sw(b, n, 0xFE, 0xFF)) return "UTF-16BE BOM";
        if (Sw(b, n, 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65)) return "SQLite";
        return "-";
    }
    // number of i in [0, len) with p[i] == p[i + k]
    static int CountEqual(byte* p, int len, int k) {
        const ulong L7 = 0x7F7F7F7F7F7F7F7FUL, H = 0x8080808080808080UL, ONES = 0x0101010101010101UL;
        int m = 0, i = 0;
        for (; i + 8 <= len; i += 8) {
            ulong x = *(ulong*)(p + i) ^ *(ulong*)(p + i + k);
            ulong nz = (((x & L7) + L7) | x) & H;          // high bit set = byte differs
            m += 8 - (int)(((nz >> 7) * ONES) >> 56);
        }
        for (; i < len; i++) if (p[i] == p[i + k]) m++;
        return m;
    }
    // self-similarity at lag k : ratio of b[i]==b[i+k]
    static string RecLen(byte[] b, int n, int maxLag, long size, out int bestLen, out double bestScore) {
        bestLen = 0; bestScore = 0;
        int lim = Math.Min(maxLag, n / 2);
        if (lim < 2) return "-";
        double[] sc = new double[lim + 1];
        // lags are independent : computed in parallel, 8 bytes per step (same result as byte by byte)
        GCHandle h = GCHandle.Alloc(b, GCHandleType.Pinned);
        try {
            IntPtr addr = h.AddrOfPinnedObject();
            Parallel.For(2, lim + 1, delegate (int k) {
                int len = n - k;
                sc[k] = (double)CountEqual((byte*)addr, len, k) / len;
            });
        } finally { h.Free(); }
        List<int> ks = new List<int>();
        for (int k = 2; k <= lim; k++) ks.Add(k);
        ks.Sort(delegate (int a, int c) { int r = sc[c].CompareTo(sc[a]); return r != 0 ? r : a.CompareTo(c); });
        int best = ks[0]; int bs = best;
        for (int k = 2; k <= best; k++) { if (sc[k] >= sc[best] * 0.95) { bs = k; break; } }
        bestLen = bs; bestScore = sc[bs] * 100;
        StringBuilder s = new StringBuilder();
        s.Append("base=").Append(bs).Append(" (").Append((sc[bs] * 100).ToString("0.0")).Append("%)");
        if (size % bs == 0) s.Append("(div)");
        s.Append(" | top:");
        for (int i = 0; i < Math.Min(5, ks.Count); i++) {
            int k = ks[i];
            s.Append(' ').Append(k).Append('=').Append((sc[k] * 100).ToString("0.0")).Append('%');
            if (size % k == 0) s.Append("(div)");
        }
        return s.ToString();
    }
    public static DatInfo Analyze(string path, int sampleMax, int maxLag) {
        DatInfo d = new DatInfo();
        long[] cnt = new long[256];
        byte[] sample = new byte[Math.Max(sampleMax, 16)];
        int sn = 0; long n = 0;
        using (SHA256 sha = SHA256.Create())
        using (FileStream fs = Open(path)) {
            byte[] buf = new byte[1048576]; int r;
            while ((r = ReadFull(fs, buf, buf.Length)) > 0) {
                sha.TransformBlock(buf, 0, r, null, 0);
                for (int i = 0; i < r; i++) cnt[buf[i]]++;
                if (sn < sample.Length) { int c = Math.Min(r, sample.Length - sn); Buffer.BlockCopy(buf, 0, sample, sn, c); sn += c; }
                n += r;
                if (r < buf.Length) break;
            }
            sha.TransformFinalBlock(new byte[0], 0, 0);
            d.Sha256 = BitConverter.ToString(sha.Hash).Replace("-", "");
        }
        d.Size = n;
        long pr = cnt[9] + cnt[10] + cnt[13];
        for (int i = 32; i < 127; i++) pr += cnt[i];
        long hi = 0;
        for (int i = 128; i < 256; i++) hi += cnt[i];
        double e = 0;
        if (n > 0) { for (int i = 0; i < 256; i++) { if (cnt[i] > 0) { double p = (double)cnt[i] / n; e -= p * Math.Log(p, 2); } } }
        d.Printable = n > 0 ? 100.0 * pr / n : 0;
        d.Zero = n > 0 ? 100.0 * cnt[0] / n : 0;
        d.High = n > 0 ? 100.0 * hi / n : 0;
        d.Entropy = e; d.LF = cnt[10]; d.CR = cnt[13];
        StringBuilder hh = new StringBuilder();
        for (int i = 0; i < Math.Min(sn, 16); i++) { if (i > 0) hh.Append(' '); hh.Append(HX[sample[i]]); }
        d.HeadHex = hh.ToString();
        d.Magic = Magic(sample, sn);
        if (n == 0) d.Type = "empty";
        else if (d.Printable >= 95.0) d.Type = "text (ASCII)";
        else if (cnt[0] == 0 && d.Printable + d.High >= 98.0 && cnt[10] > 0) d.Type = "text (MBCS/Shift-JIS?)";
        else if (e > 7.5) d.Type = "binary (high entropy: compressed/encrypted/image?)";
        else d.Type = "binary";
        int bl; double bsc;
        d.RecLen = RecLen(sample, sn, maxLag, n, out bl, out bsc);
        d.BestLen = bl; d.BestScore = bsc;
        return d;
    }
    const string HEXD = "0123456789ABCDEF";
    // "OOOOOOOO  hh hh hh hh hh hh hh hh  hh hh hh hh hh hh hh hh  ascii" ; returns length
    static int HexLine(char[] ln, long offset, byte[] buf, int at, int c) {
        int q = 0;
        if (offset > 0xFFFFFFFFL) { foreach (char ch in offset.ToString("X8")) ln[q++] = ch; }
        else for (int s = 28; s >= 0; s -= 4) ln[q++] = HEXD[(int)((offset >> s) & 0xF)];
        ln[q++] = ' '; ln[q++] = ' ';
        for (int j = 0; j < 16; j++) {
            if (j < c) { byte v = buf[at + j]; ln[q++] = HEXD[v >> 4]; ln[q++] = HEXD[v & 0xF]; ln[q++] = ' '; }
            else { ln[q++] = ' '; ln[q++] = ' '; ln[q++] = ' '; }
            if (j == 7) ln[q++] = ' ';
        }
        ln[q++] = ' ';
        for (int j = 0; j < c; j++) { byte v = buf[at + j]; ln[q++] = v >= 32 && v < 127 ? (char)v : '.'; }
        return q;
    }
    public static long Dump(string src, TextWriter w, long limit, int textCp) {
        long off = 0;
        {
            if (textCp > 0) {
                w.WriteLine("[TEXT VIEW (codepage " + textCp + ")]");
                using (StreamReader sr = new StreamReader(Open(src), Encoding.GetEncoding(textCp), true)) {
                    string line; long ln = 0;
                    while ((line = sr.ReadLine()) != null) { ln++; w.Write(ln.ToString().PadLeft(7)); w.Write(": "); w.WriteLine(line); }
                }
                w.WriteLine();
            }
            w.WriteLine("[HEX DUMP]");
            w.WriteLine("Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII");
            using (FileStream fs = Open(src)) {
                byte[] buf = new byte[1048576]; char[] ln = new char[96]; int r;
                while ((r = ReadFull(fs, buf, buf.Length)) > 0) {
                    if (limit > 0 && off + r > limit) r = (int)(limit - off);
                    for (int i = 0; i < r; i += 16) {
                        int c = Math.Min(16, r - i);
                        int q = HexLine(ln, off + i, buf, i, c);
                        w.Write(ln, 0, q); w.WriteLine();
                    }
                    off += r;
                    if (limit > 0 && off >= limit) break;
                    if (r < buf.Length) break;
                }
            }
            w.WriteLine("[END: " + off + " bytes dumped]");
        }
        return off;
    }
}
}
