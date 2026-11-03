using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using FolderScan.Core;

namespace FolderScan.App {
    // Prompt loop of folderscan (":ASK" of v5.18) and execution of single / batch jobs.
    public sealed class ConsoleShell {
        readonly ScanRunner runner;
        readonly TargetResolver resolver;
        readonly IReportViewer viewer;
        readonly IFolderPicker picker;
        readonly ISettingsMenu settingsMenu;
        readonly Settings settings;
        readonly string outDir;

        public ConsoleShell(ScanRunner runner, TargetResolver resolver, IReportViewer viewer, IFolderPicker picker, ISettingsMenu settingsMenu, Settings settings, string outDir) {
            this.runner = runner; this.resolver = resolver; this.viewer = viewer; this.picker = picker; this.settingsMenu = settingsMenu; this.settings = settings; this.outDir = outDir;
        }

        // read at every scan, so a change in the settings menu applies at once
        bool Open { get { return settings.OpenResult == 1; } }

        public void Loop() {
            while (true) {
                string input = Ask();
                if (input == null) break;
                if (input.Length == 0) continue;
                Execute(resolver.Resolve(input));
            }
            Console.WriteLine();
            Console.WriteLine("Output folder: " + outDir);
        }

        // null = quit, "" = nothing to do
        string Ask() {
            Console.WriteLine();
            Console.WriteLine("------------------------------------------------------------");
            Console.WriteLine(" Enter target folder path - all subfolders are included");
            Console.WriteLine(" example: \\\\server\\share\\2026\\2026_10\\2026_10_13");
            Console.WriteLine(" C:\\work\\apps\\*  = scan every folder directly under C:\\work\\apps one by one");
            Console.WriteLine(" *               = scan every folder next to this bat one by one");
            Console.WriteLine(" @list.txt       = scan every folder listed in the file - one path per line");
            Console.WriteLine(" Empty Enter     = choose the folder in a dialog");
            Console.WriteLine(" s               = settings (saved for this PC, kept when the tool is updated)");
            Console.WriteLine(" q               = exit");
            Console.WriteLine("------------------------------------------------------------");
            Console.Write("> ");
            string s = Console.ReadLine();
            if (s == null) return null;
            s = s.Trim();
            if (s.Equals("q", StringComparison.OrdinalIgnoreCase) || s.Equals("quit", StringComparison.OrdinalIgnoreCase) || s.Equals("exit", StringComparison.OrdinalIgnoreCase)) return null;
            if (s.Equals("s", StringComparison.OrdinalIgnoreCase)) { settingsMenu.Run(); return ""; }
            if (s.Length > 0) return s;
            string p = picker.Pick();
            if (p == null) { Console.WriteLine("(cancelled)"); return ""; }
            Console.WriteLine("> " + p);
            return p;
        }

        public void Execute(ScanJob job) {
            if (job.Error != null) {
                Console.WriteLine();
                Console.WriteLine("[ERROR] " + job.Error);
                return;
            }
            if (!job.IsBatch) {
                ScanResult r = runner.Run(job.Targets[0], outDir, null);
                if (r.ReportPath == null) return;
                if (Open) viewer.Open(r.GapsPath != null && File.Exists(r.GapsPath) ? r.GapsPath : r.ReportPath);
                return;
            }
            string bts = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
            string batch = Path.Combine(outDir, "batch_gaps_" + bts + ".txt");
            Console.WriteLine();
            Console.WriteLine("Batch gaps   : " + batch);
            Console.WriteLine(job.Description);
            foreach (string t in job.Targets) runner.Run(t, outDir, batch);
            if (File.Exists(batch)) { Console.WriteLine("  Batch gaps : " + batch); if (Open) viewer.Open(batch); }
        }
    }
}
