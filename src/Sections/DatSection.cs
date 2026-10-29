using System;
using System.Collections.Generic;
using System.IO;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [7] DAT FILES : ANALYSIS INDEX
    // [8] DAT FILES : FULL DUMP
    // .dat files of the target and (DATINCAB=1) .dat files extracted from cab.
    public sealed class DatSection : IReportSection {
        sealed class DatSrc { public string Src; public string Cab; public string Root; public FileInfo File; }
        sealed class DatRow { public int No; public DatSrc E; public string Rel; public DatInfo A; public string Err; }

        public void Write(ScanContext c) {
            c.Progress("[7/19] DAT analysis...");
            c.L("==== [7] DAT FILES : ANALYSIS INDEX (full dump in [8]) ====");
            List<DatSrc> list = Sources(c);
            if (list.Count == 0) { c.L("(no dat file found)"); c.L(); return; }

            List<DatRow> idx = Analyze(c, list);
            WriteIndex(c, idx);
            WriteDump(c, idx);
        }

        static bool IsDat(FileInfo f) { return string.Equals(f.Extension, ".dat", StringComparison.OrdinalIgnoreCase); }

        static List<DatSrc> Sources(ScanContext c) {
            List<DatSrc> list = new List<DatSrc>();
            foreach (FileInfo f in c.AllFiles) if (IsDat(f)) list.Add(Src("target", "", c.ScanRoot, f));
            if (c.Settings.DatInCab == 1) {
                foreach (CabEntry m in c.CabMap) {
                    List<FileInfo> l = new List<FileInfo>();
                    foreach (FileInfo f in FileCollector.FilesUnder(m.Dir)) if (IsDat(f)) l.Add(f);
                    PathUtil.SortByFullName(l);
                    foreach (FileInfo f in l) list.Add(Src("cab#" + m.No, m.Cab, m.Dir, f));
                }
            }
            return list;
        }

        static DatSrc Src(string src, string cab, string root, FileInfo f) {
            DatSrc d = new DatSrc(); d.Src = src; d.Cab = cab; d.Root = root; d.File = f;
            return d;
        }

        static List<DatRow> Analyze(ScanContext c, List<DatSrc> list) {
            List<DatRow> idx = new List<DatRow>();
            int no = 0;
            c.Progress("  analyzing...");
            foreach (DatSrc e in list) {
                no++;
                DatRow r = new DatRow(); r.No = no; r.E = e; r.Rel = PathUtil.Rel(e.Root, e.File.FullName); r.Err = "";
                c.Progress(string.Format("  [{0}/{1}] analyze {2}  {3}", no, list.Count, e.Src, r.Rel));
                try { r.A = DatTool.Analyze(e.File.FullName, c.Settings.RecSample, c.Settings.RecLag); }
                catch (Exception ex) { r.A = null; r.Err = ex.Message; }
                idx.Add(r);
                if (r.A != null) c.DatA[e.File.FullName] = r.A;
            }
            return idx;
        }

        static void WriteIndex(ScanContext c, List<DatRow> idx) {
            c.L("DAT files : " + idx.Count);
            c.L();
            TextTable t = new TextTable("No:r", "Source", "Path", "Bytes:r", "Type", "Magic", "Entropy:r", "RecLen");
            foreach (DatRow r in idx) {
                if (r.A != null) t.Add(r.No, r.E.Src, r.Rel, r.A.Size, r.A.Type, r.A.Magic, Math.Round(r.A.Entropy, 3), r.A.RecLen);
                else t.Add(r.No, r.E.Src, r.Rel, r.E.File.Length, "ERROR", "", "", "");
            }
            c.Report.Table(t);
            c.L();
            if (c.CabMap.Count > 0) { c.L("[Source cab#N = see extract map in [5]]"); c.L(); }
            c.L("[duplicate content (same SHA256)]");
            Dictionary<string, List<DatRow>> bySha = new Dictionary<string, List<DatRow>>(StringComparer.OrdinalIgnoreCase);
            List<string> order = new List<string>();
            foreach (DatRow r in idx) {
                if (r.A == null || string.IsNullOrEmpty(r.A.Sha256) || r.A.Sha256 == "-") continue;
                List<DatRow> l;
                if (!bySha.TryGetValue(r.A.Sha256, out l)) { l = new List<DatRow>(); bySha[r.A.Sha256] = l; order.Add(r.A.Sha256); }
                l.Add(r);
            }
            int dup = 0;
            foreach (string h in order) {
                List<DatRow> g = bySha[h];
                if (g.Count < 2) continue;
                dup++;
                c.L("  " + h.Substring(0, 16) + "... x" + g.Count);
                foreach (DatRow x in g) c.L("      " + x.E.Src + "  " + x.Rel);
            }
            if (dup == 0) c.L("(none)");
            c.L();
        }

        static void WriteDump(ScanContext c, List<DatRow> idx) {
            Settings s = c.Settings;
            long limit = s.DatMaxBytes;
            c.Progress("[8/19] DAT full dump...");
            c.L("==== [8] DAT FILES : FULL DUMP ====");
            if (s.DumpDat != 1) c.L(" DUMPDAT=0 : the dump itself is omitted (analysis above is complete). Set DUMPDAT=1, or list files in DUMPFILES (settings.ini), to output it.");
            c.L();
            string bar = new string('#', 78);
            foreach (DatRow x in idx) {
                DatSrc e = x.E; FileInfo f = e.File; DatInfo a = x.A;
                c.Progress(string.Format("  [{0}/{1}] dump {2}  {3}", x.No, idx.Count, e.Src, x.Rel));
                c.L(bar);
                c.L("# DAT No." + x.No + "  " + e.Src + "  " + x.Rel);
                c.L(bar);
                c.L(e.Cab.Length > 0 ? "Source    : " + e.Cab + " -> " + x.Rel : "Source    : " + f.FullName);
                c.L("Modified  : " + PathUtil.Time(f.LastWriteTime));
                if (a == null) { c.L("read error: " + x.Err); c.L(); continue; }
                c.L("Bytes     : " + a.Size);
                c.L("SHA256    : " + a.Sha256);
                c.L("Type      : " + a.Type);
                c.L("Magic     : " + a.Magic);
                c.L("Head16    : " + a.HeadHex);
                c.L(string.Format("Printable : {0:N2} %   Zero : {1:N2} %   High(>=0x80) : {2:N2} %", a.Printable, a.Zero, a.High));
                c.L(string.Format("Entropy   : {0:N3} bits/byte (0=uniform, 8=random)", a.Entropy));
                c.L("Lines     : LF=" + a.LF + "  CR=" + a.CR);
                c.L("RecLen    : " + a.RecLen);
                c.L("            (byte match ratio at lag k in first " + s.RecSample + " bytes, (div)=divides file size)");
                if (limit > 0) c.L("DumpLimit : first " + s.DatMaxMb + " MB only");
                c.L();
                if (!s.WantDump(s.DumpDat == 1, x.Rel, f.Name)) {
                    c.L("[DUMP OMITTED] DUMPDAT=0 : set DUMPDAT=1 or add this file to DUMPFILES in settings.ini to output the full dump");
                    c.OmittedDat.Add(e.Src + " " + x.Rel);
                    c.L();
                    continue;
                }
                try {
                    c.Report.Flush();
                    int tcp = (a.Type ?? "").StartsWith("text", StringComparison.OrdinalIgnoreCase) ? c.FileCp(f.FullName) : 0;
                    DatTool.Dump(f.FullName, c.Report.Writer, limit, tcp);
                } catch (Exception ex) { c.L("dump error: " + ex.Message); }
                c.L();
            }
        }
    }
}
