using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [10] CONTENT AND DATA STRUCTURE PER FILE
    // Files are analyzed in parallel in small blocks (memory stays bounded) and
    // written in file order, so the report is the same as a sequential run.
    public sealed class ContentSection : IReportSection {
        public void Write(ScanContext c) {
            c.Progress("[10/19] Content / data structure per file...");
            c.L("==== [10] CONTENT AND DATA STRUCTURE PER FILE ====");
            c.L(" [TEXT]    full text with line No. (text .dat : see [8])");
            if (c.Settings.DumpText != 1) c.L("           DUMPTEXT=0 : the full text / strings are omitted (counts and analysis are complete). Set DUMPTEXT=1, or list files in DUMPFILES (settings.ini), to output them.");
            c.L(" [STRINGS] printable ASCII runs in binary files with byte offset");
            c.L(" [TABLE]   delimited text : columns, numeric ratio, distinct count, examples");
            c.L(" [FIELDS]  fixed-width lines / fixed-length records : estimated fields");
            c.L("           Class CONST=same in all records  NUM=digits  TEXT=ASCII");
            c.L("                 MBCS=Japanese text?  BIN=binary  CONSTB=same binary");
            c.L("           (record assumed to start at offset 0, header not considered)");
            c.L(" [KEYS]    number of candidate key values collected (used in [12])");
            c.L(" [SEM]     counts of semantic items collected (used in [15]-[17])");
            c.L();
            LinkState k = c.Link;
            ContentAnalyzer an = new ContentAnalyzer(c.Settings, c.DatA, k.Names, k.DbX);
            int block = Math.Max(2, Environment.ProcessorCount * 2);
            for (int start = 0; start < k.Fx.Count; start += block) {
                int n = Math.Min(block, k.Fx.Count - start);
                ContentResult[] res = new ContentResult[n];
                int st = start;
                Parallel.For(0, n, delegate (int i) { res[i] = an.Analyze(k.Fx[st + i]); });
                foreach (ContentResult r in res) Merge(c, r);
            }
            SemTool.FinalizeWraps(k.Wraps, c.Settings.WrapDepth);
        }

        // Writes one file block and adds its results to the shared state (in file order).
        static void Merge(ScanContext c, ContentResult r) {
            LinkState k = c.Link;
            FileEntry x = r.X;
            c.Progress(string.Format("  [{0}/{1}] {2}  {3}", x.No, k.Fx.Count, x.Src, x.Rel));
            c.Report.Writer.Write(r.Pre.ToString());
            if (r.Units != null) LinkTool.WriteUnits(r.Units, c.Report.Writer);
            if (r.Omitted) c.OmittedText.Add(x.Display);
            c.Report.Writer.Write(r.Post.ToString());
            if (r.Keys == null) return;   // not analyzed : no keys / refs / semantic items
            k.Keys.Add(x.No, r.Keys);
            k.Refs.AddRange(r.Refs);
            foreach (Wrap w in r.Wrappers) {
                k.WrapAll.Add(w);
                string wk = x.Lang + "|" + w.Name;
                Wrap old;
                if (!k.Wraps.TryGetValue(wk, out old)) k.Wraps[wk] = w;
                else if (w.Http && !old.Http) k.Wraps[wk] = w;
            }
            k.Sem[x.No] = r.Sem;
        }
    }
}
