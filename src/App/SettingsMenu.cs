using System;
using System.Collections.Generic;
using FolderScan.Core;

namespace FolderScan.App {
    // Opened with "s" at the folderscan prompt.
    public interface ISettingsMenu {
        void Run();
    }

    // Console menu for the settings of this PC.
    //   list   : grouped by the [sections] of settings.ini, one number per key, * = value of this PC
    //   input  : number or key name -> shows the explanation and asks for the new value
    //            KEY=value          -> changes at once
    //            r                  -> all values of this PC back to settings.ini
    //            l                  -> list again
    //            Enter              -> back to the folder prompt
    public sealed class ConsoleSettingsMenu : ISettingsMenu {
        readonly SettingsEditor editor;
        readonly string iniPath;
        List<IniItem> rows;

        public ConsoleSettingsMenu(SettingsEditor editor, string iniPath) { this.editor = editor; this.iniPath = iniPath; }

        public void Run() {
            rows = Rows();
            List();
            while (true) {
                Console.WriteLine();
                Console.Write("settings> ");
                string s = Console.ReadLine();
                if (s == null) return;
                s = s.Trim();
                if (s.Length == 0 || s.Equals("q", StringComparison.OrdinalIgnoreCase)) { Console.WriteLine("(back to the folder prompt ; changed values are used from the next scan)"); return; }
                if (s.Equals("l", StringComparison.OrdinalIgnoreCase)) { List(); continue; }
                if (s.Equals("r", StringComparison.OrdinalIgnoreCase)) { ResetAll(); continue; }
                int eq = s.IndexOf('=');
                if (eq > 0) { Show(editor.Change(s.Substring(0, eq).Trim(), s.Substring(eq + 1).Trim())); continue; }
                IniItem it = Pick(s);
                if (it == null) { Color(ConsoleColor.Red, "  not found : " + s + "   (number / key name / KEY=value / l / r / Enter)"); continue; }
                Edit(it);
            }
        }

        // ini order first (with its sections and comments), then keys that are not in settings.ini
        List<IniItem> Rows() {
            List<IniItem> r = new List<IniItem>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (IniItem it in IniFile.ReadDoc(iniPath)) {
                SettingDef d = SettingDefs.Find(it.Key);
                if (d == null || !seen.Add(d.Key)) continue;
                it.Key = d.Key;
                r.Add(it);
            }
            foreach (SettingDef d in SettingDefs.All) {
                if (seen.Contains(d.Key)) continue;
                IniItem it = new IniItem(); it.Section = "(not in settings.ini)"; it.Key = d.Key;
                r.Add(it);
            }
            return r;
        }

        void List() {
            Console.WriteLine();
            Console.WriteLine("============================================================");
            Console.WriteLine(" Settings   * = value of this PC (kept when settings.ini is updated)");
            Console.WriteLine(" PC file    : " + editor.PcPath);
            Console.WriteLine("============================================================");
            string sec = null;
            for (int i = 0; i < rows.Count; i++) {
                IniItem it = rows[i];
                if (it.Section != sec) { sec = it.Section; Console.WriteLine(" [" + sec + "]"); }
                bool pc = editor.IsPc(it.Key);
                string line = string.Format("  {0,3} {1} {2,-12} {3}", i + 1, pc ? "*" : " ", it.Key, Cut(editor.Settings.Get(it.Key), 56));
                if (pc) Color(ConsoleColor.Cyan, line); else Console.WriteLine(line);
            }
            Console.WriteLine("------------------------------------------------------------");
            Console.WriteLine(" number or key = change   KEY=value = change at once   l = list");
            Console.WriteLine(" r = all * back to settings.ini   Enter = back");
        }

        void Edit(IniItem it) {
            Console.WriteLine();
            Color(ConsoleColor.White, " " + it.Key + (it.Section.Length > 0 ? "   [" + it.Section + "]" : ""));
            foreach (string h in it.Help) Console.WriteLine("   " + h);
            string origin;
            string b = editor.BaseValue(it.Key, out origin);
            Console.WriteLine("   " + (origin == Settings.FromIni ? "settings.ini" : "default     ") + " : " + b);
            Console.WriteLine("   now          : " + editor.Settings.Get(it.Key) + (editor.IsPc(it.Key) ? "   (* this PC)" : ""));
            Console.WriteLine("   new value  (Enter = keep" + (editor.IsPc(it.Key) ? " / - = back to " + (origin == Settings.FromIni ? "settings.ini" : "default") : "") + ")");
            Console.Write("   > ");
            string v = Console.ReadLine();
            if (v == null || v.Trim().Length == 0) { Console.WriteLine("   (not changed)"); return; }
            if (v.Trim() == "-") { Show(editor.Revert(it.Key)); return; }
            Show(editor.Change(it.Key, v.Trim()));
        }

        void ResetAll() {
            List<EditResult> l = editor.RevertAll();
            if (l.Count == 0) { Console.WriteLine("  (no value of this PC)"); return; }
            foreach (EditResult r in l) Show(r);
        }

        void Show(EditResult r) {
            if (!r.Ok) { Color(ConsoleColor.Red, "  [not saved] " + (r.Key.Length > 0 ? r.Key + " : " : "") + r.Error); return; }
            if (!r.Changed) { Console.WriteLine("  (no change) " + r.Key + " = " + r.New); return; }
            string where = editor.IsPc(r.Key) ? "this PC" : "settings.ini value";
            Color(ConsoleColor.Green, "  [saved] " + r.Key + " : " + Cut(r.Old, 30) + " -> " + Cut(r.New, 30) + "   (" + where + ")");
        }

        IniItem Pick(string s) {
            int n;
            if (int.TryParse(s, out n)) return n >= 1 && n <= rows.Count ? rows[n - 1] : null;
            foreach (IniItem it in rows) if (it.Key.Equals(s, StringComparison.OrdinalIgnoreCase)) return it;
            return null;
        }

        static string Cut(string s, int max) {
            s = s ?? "";
            if (s.Length == 0) return "(empty)";
            return s.Length <= max ? s : s.Substring(0, max - 3) + "...";
        }

        static void Color(ConsoleColor c, string line) {
            ConsoleColor old = ConsoleColor.Gray;
            try { old = Console.ForegroundColor; Console.ForegroundColor = c; } catch { }
            Console.WriteLine(line);
            try { Console.ForegroundColor = old; } catch { }
        }
    }
}
