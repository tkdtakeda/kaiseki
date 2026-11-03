using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using FolderScan.Core;
using FolderScan.Sections;

namespace FolderScan.App {
    // Entry point. Started by folderscan.bat.
    //   folderscan.exe --home <folder of the bat> [--settings <ini>] [folder ...]
    //   folderscan.exe --home <folder> --argsenv   (folders are read from FOLDERSCAN_ARGS)
    //   folderscan.exe --selftest                  (prints ok; used by the bat)
    //   folderscan.exe --compare <old> <new> [out] (migration check, see ReportCompare)
    public static class Program {
        [STAThread]
        public static int Main(string[] args) {
            string home = AppDomain.CurrentDomain.BaseDirectory;
            string ini = null;
            List<string> paths = new List<string>();
            for (int i = 0; i < args.Length; i++) {
                string a = args[i];
                if (a == "--selftest") { Console.WriteLine("ok"); return 0; }
                if (a == "--compare" && i + 2 < args.Length) return ReportCompare.Run(args[i + 1], args[i + 2], i + 3 < args.Length ? args[i + 3] : null);
                if (a == "--home" && i + 1 < args.Length) { home = args[++i]; continue; }
                if (a == "--settings" && i + 1 < args.Length) { ini = args[++i]; continue; }
                if (a == "--argsenv") { paths.AddRange(SplitArgs(Environment.GetEnvironmentVariable("FOLDERSCAN_ARGS"))); continue; }
                paths.Add(a);
            }
            home = Path.GetFullPath(home);
            if (ini == null) ini = Path.Combine(home, "settings.ini");

            try { Console.Title = "folderscan " + ScanContext.Version + " - structure / content / data structure / linkage / database / semantic dependency (read-only target)"; } catch { }
            IConsoleLog log = new ConsoleLog();
            UserSettingsStore pc = UserSettingsStore.Load(UserSettingsStore.DefaultPath());
            Settings settings = SettingsLoader.Load(ini, pc);
            settings.Home = home;
            foreach (string w in settings.Warnings) log.Info("  [warn] " + w);
            log.Info("Settings : " + settings.Describe());

            string outDir = OutputLocator.Resolve();
            log.Info("Output folder: " + outDir);

            ScanRunner runner = new ScanRunner(settings, log, SectionRegistry.Default);
            TargetResolver resolver = new TargetResolver(home, outDir);
            ISettingsMenu menu = new ConsoleSettingsMenu(new SettingsEditor(settings, pc, ini), ini);
            ConsoleShell shell = new ConsoleShell(runner, resolver, new NotepadViewer(), new DialogFolderPicker(), menu, settings, outDir);

            if (paths.Count > 0) shell.Execute(resolver.ResolveMany(paths));
            shell.Loop();
            Console.WriteLine("Press Enter to close . . .");
            Console.ReadLine();
            return 0;
        }

        // Splits a command line the way cmd passes %* ("a b" c -> [a b] [c]).
        static List<string> SplitArgs(string s) {
            List<string> r = new List<string>();
            if (string.IsNullOrEmpty(s)) return r;
            StringBuilder cur = new StringBuilder(); bool q = false, any = false;
            foreach (char ch in s) {
                if (ch == '"') { q = !q; any = true; continue; }
                if (!q && (ch == ' ' || ch == '\t')) { if (any) { r.Add(cur.ToString()); cur.Length = 0; any = false; } continue; }
                cur.Append(ch); any = true;
            }
            if (any) r.Add(cur.ToString());
            return r;
        }
    }
}
