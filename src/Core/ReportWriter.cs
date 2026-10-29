using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace FolderScan.Core {
    // Report output (functions L / TSV of v5.18). UTF-8 with BOM, CRLF.
    public sealed class ReportWriter : IDisposable {
        readonly StreamWriter w;
        public string Path { get; private set; }

        ReportWriter(StreamWriter w, string path) { this.w = w; Path = path; }

        // Writer is the raw stream, used by helpers that dump directly (DatTool.Dump).
        public TextWriter Writer { get { return w; } }

        // Opens the report at the first writable candidate path.
        public static ReportWriter Open(IList<string> candidates, IConsoleLog log) {
            foreach (string p in candidates) {
                try {
                    Directory.CreateDirectory(System.IO.Path.GetDirectoryName(p));
                    StreamWriter sw = new StreamWriter(p, false, new UTF8Encoding(true), 1048576);
                    if (p != candidates[0]) {
                        log.Info("  [warn] could not write to " + candidates[0]);
                        log.Info("         report is written to " + p);
                    }
                    return new ReportWriter(sw, p);
                } catch (Exception ex) { log.Info("  [warn] " + ex.Message); }
            }
            return null;
        }

        public void L() { w.WriteLine(); }
        public void L(string s) { w.WriteLine(s); }

        // Machine readable block : #TSV-BEGIN name / header / rows / #TSV-END
        public void Tsv(string name, string[] head, IEnumerable<string[]> rows) { WriteTsv(w, name, head, rows); }

        // Same block into any writer (used for per-file buffers built in parallel).
        public static void WriteTsv(TextWriter o, string name, string[] head, IEnumerable<string[]> rows) {
            o.WriteLine("#TSV-BEGIN " + name);
            o.WriteLine(string.Join("\t", head));
            foreach (string[] r in rows) o.WriteLine(string.Join("\t", r));
            o.WriteLine("#TSV-END");
        }

        // Equivalent of: L (($rows | Format-Table -AutoSize | Out-String).TrimEnd())
        public void Table(TextTable t) { L(t.Render()); }

        public void Flush() { w.Flush(); }
        public void Dispose() { w.Dispose(); }
    }
}
