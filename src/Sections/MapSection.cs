using System;
using System.IO;
using System.Text;
using FolderScan.Core;
using FolderScan.Diag;
using FolderScan.Map;

namespace FolderScan.Sections {
    // System map : one html file (opens in Edge without a server) built from templates\map.*
    //   <scan folder>\map.html and <output>\latest_map.html
    public sealed class MapSection : IReportSection {
        public void Write(ScanContext c) {
            if (c.Settings.Map != 1) return;
            c.Progress("[map] System map...");
            try {
                string dir = Path.Combine(c.Settings.Home, "templates");
                string html = Read(dir, "map.html"), css = Read(dir, "map.css"), js = Read(dir, "map.js");
                if (html == null || css == null || js == null) { c.Log.Info("  [warn] templates\\map.html / map.css / map.js not found in " + dir + " : map not written"); return; }
                // json inside <script> : "</" must not end the script element
                string data = Json.Write(SystemMapBuilder.Build(c)).Replace("</", "<\\/");
                string title = "folderscan map - " + Path.GetFileName(c.ScanRoot.TrimEnd('\\', '/'));
                string page = html.Replace("{{TITLE}}", Esc(title)).Replace("{{CSS}}", css).Replace("{{JS}}", js).Replace("{{DATA}}", data);
                string path = Path.Combine(c.RunDir, "map.html");
                File.WriteAllText(path, page, new UTF8Encoding(true));
                string latest = Path.Combine(c.OutRoot, "latest_map.html");
                try { File.WriteAllText(latest, page, new UTF8Encoding(true)); c.MapPath = latest; } catch (Exception ex) { c.Log.Info("  [warn] latest_map.html: " + ex.Message); c.MapPath = path; }
            } catch (Exception ex) { c.Log.Info("  [warn] system map failed: " + ex.Message); }
        }

        static string Read(string dir, string name) {
            string p = Path.Combine(dir, name);
            return File.Exists(p) ? File.ReadAllText(p, Encoding.UTF8) : null;
        }

        static string Esc(string s) { return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;"); }
    }
}
