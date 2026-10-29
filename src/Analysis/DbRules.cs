using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using FolderScan.Core;

namespace FolderScan.Analysis {
    // One database indicator / database file name found in a content unit ([16-5b]).
    public sealed class DbHit {
        public string Loc;
        public bool IsFile;     // true = name of a database file, false = connection/API indicator
        public string Value;    // indicator word or file name
        public int DbNo;        // file No. of the database file (IsFile only)
    }

    // Database files and references (v5.18 [16-5a] / [16-5b]).
    public static class DbRules {
        static readonly Regex Api = new Regex(@"(?i)\b(SqlConnection|SqlCommand|OleDbConnection|OdbcConnection|SQLiteConnection|SqliteConnection|AttachDbFilename|Initial Catalog|Data Source|Database|Server)\b");
        static readonly Regex LogSuffix = new Regex("(?i)_log$");

        public static string Role(FileEntry q) {
            switch (q.Ext) {
                case ".mdf": return "sqlserver-data";
                case ".ldf": return "sqlserver-log";
                case ".sqlite": case ".sqlite3": return "sqlite";
                case ".mdb": case ".accdb": return "access";
                case ".db": return "generic-db";
                default: return "";
            }
        }

        // folder + base name, "_log" removed for .ldf (pairs x.mdf with x_log.ldf)
        public static string Key(FileEntry q) {
            string bn = System.IO.Path.GetFileNameWithoutExtension(q.File.Name);
            if (q.Ext == ".ldf") bn = LogSuffix.Replace(bn, "");
            return (q.File.DirectoryName.TrimEnd('\\') + "\\" + bn).ToLowerInvariant();
        }

        public static List<FileEntry> Files(List<FileEntry> fx) {
            List<FileEntry> l = new List<FileEntry>();
            foreach (FileEntry x in fx) if (Role(x).Length > 0) l.Add(x);
            return l;
        }

        // Collected while the content is in memory ([10]) so the file is not read again.
        public static List<DbHit> Scan(FileEntry x, List<Unit> u, List<FileEntry> dbX) {
            List<DbHit> o = new List<DbHit>();
            foreach (Unit z in u) {
                foreach (Match m in Api.Matches(z.Text)) { DbHit h = new DbHit(); h.Loc = z.Loc; h.Value = m.Groups[1].Value; o.Add(h); }
                foreach (FileEntry d in dbX) {
                    if (x.No == d.No) continue;
                    if (z.Text.IndexOf(d.File.Name, StringComparison.OrdinalIgnoreCase) >= 0) {
                        DbHit h = new DbHit(); h.Loc = z.Loc; h.IsFile = true; h.Value = d.File.Name; h.DbNo = d.No; o.Add(h);
                    }
                }
            }
            return o;
        }
    }
}
