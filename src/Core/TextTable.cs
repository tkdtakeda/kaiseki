using System;
using System.Collections.Generic;
using System.Text;

namespace FolderScan.Core {
    // Text table in the layout of PowerShell "Format-Table -AutoSize | Out-String".
    //   (blank line)
    //   header      : numbers right aligned, text left aligned, 1 space between columns
    //   dashes      : as long as the header text
    //   rows
    // Trailing spaces are removed. Long values are never truncated.
    public sealed class TextTable {
        sealed class Col { public string Name; public bool Right; }
        readonly List<Col> cols = new List<Col>();
        readonly List<string[]> rows = new List<string[]>();

        // name ending with ":r" = right aligned (numeric) column
        public TextTable(params string[] columns) {
            foreach (string c in columns) {
                Col x = new Col();
                if (c.EndsWith(":r")) { x.Name = c.Substring(0, c.Length - 2); x.Right = true; } else x.Name = c;
                cols.Add(x);
            }
        }

        public int Count { get { return rows.Count; } }

        public void Add(params object[] values) {
            string[] r = new string[cols.Count];
            for (int i = 0; i < cols.Count; i++) r[i] = i < values.Length && values[i] != null ? Convert.ToString(values[i]) : "";
            rows.Add(r);
        }

        public string Render() {
            if (rows.Count == 0) return "";
            int[] wd = new int[cols.Count];
            for (int i = 0; i < cols.Count; i++) {
                wd[i] = cols[i].Name.Length;
                foreach (string[] r in rows) if (r[i].Length > wd[i]) wd[i] = r[i].Length;
            }
            StringBuilder sb = new StringBuilder();
            sb.Append("\r\n");
            Line(sb, wd, delegate (int i) { return cols[i].Name; });
            Line(sb, wd, delegate (int i) { return new string('-', cols[i].Name.Length); });
            foreach (string[] r in rows) { string[] rr = r; Line(sb, wd, delegate (int i) { return rr[i]; }); }
            return sb.ToString().TrimEnd();
        }

        delegate string Cell(int i);

        void Line(StringBuilder sb, int[] wd, Cell cell) {
            StringBuilder ln = new StringBuilder();
            for (int i = 0; i < cols.Count; i++) {
                if (i > 0) ln.Append(' ');
                string v = cell(i);
                ln.Append(cols[i].Right ? v.PadLeft(wd[i]) : v.PadRight(wd[i]));
            }
            sb.Append(ln.ToString().TrimEnd()).Append("\r\n");
        }
    }
}
