using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace FolderScan.Core {
    // All tunable values of a scan. Defaults are the values of folderscan v5.18.
    // Values are layered by SettingsLoader : defaults -> settings.ini -> this PC (user_settings.json).
    // The list of keys and how each one is read / written is in SettingDefs.
    public sealed class Settings {
        // display
        public int OpenResult = 0;   // 1 = open the report in notepad after the scan
        public int Diag = 1;         // 1 = self diagnosis (diag_*.json / diag_*.txt / console summary)
        public int DiagTop = 10;     // findings shown on the console
        public int Map = 1;          // 1 = system map (map.html / latest_map.html)
        // raw content in scan.txt (large) : off by default, on per file with DUMPFILES
        public int DumpDat = 0;      // 1 = [8] full dump of every .dat file
        public int DumpText = 0;     // 1 = [10] full text / strings of every file
        public List<string> DumpFiles = new List<string>();   // paths or wildcards (; separated) always dumped

        // true when the raw content of this file is to be written ([8] / [10])
        public bool WantDump(bool all, string rel, string name) {
            if (all) return true;
            string r = (rel ?? "").Replace('/', '\\').TrimStart('\\');
            foreach (string p0 in DumpFiles) {
                string p = p0.Replace('/', '\\').TrimStart('\\');
                if (FolderScan.Analysis.ModuleResolver.Like(r, p) || FolderScan.Analysis.ModuleResolver.Like(name, p)) return true;
            }
            return false;
        }
        // v2
        public int MaxCab = 3;
        public int CabExt = 1;
        public int HeadBytes = 64;
        public int HexMax = 20;
        public int DatInCab = 1;
        public int DatMaxMb = 0;
        public int RecSample = 32768;
        public int RecLag = 4096;
        // v3
        public int HashAll = 1;
        public int MinStr = 4;
        public int LinkMaxMb = 0;
        public int KeyMax = 20000;
        public int KeyMaxFiles = 50;
        public int KeyTop = 10;
        public int ProfRec = 2000;
        public double RecMin = 50;
        public List<string> SkipExt = Words(".cab .zip .7z .gz .lzh .rar .jpg .jpeg .png .gif .bmp .tif .tiff .ico .mp4 .avi .wmv .mov .mp3 .wav");
        public List<string> RecExt = Words(".dat .bin (none)");
        // v4 / v5
        public int SymMin = 4;
        public int MermaidKey = 0;
        public int MermaidSym = 1;
        public int MermaidWeak = 0;
        public List<string> GenericKeys = Words("id name key value values type path file files label data item items list text title url uri img image src dest mode status kind default defaults version enabled options option config settings size width height color index count");
        // v5.10 -
        public int WrapDepth = 2;
        public int ReviewMax = 25;
        public int SnipLen = 220;
        public int GapMax = 30;
        public int GapCtx = 3;
        public int History = 1;

        public const string FromIni = "settings.ini";
        public const string FromPc = "this PC";

        public string SourcePath = "(defaults)";   // settings.ini that was read
        public string PcPath = "";                 // user_settings.json of this PC
        public string Home = "";     // folder of folderscan.bat (templates\ is read from here)
        public readonly List<string> Warnings = new List<string>();
        // key -> FromIni / FromPc ; keys not listed keep the built-in default
        public readonly Dictionary<string, string> Origin = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public long LinkMaxBytes { get { return (long)LinkMaxMb * 1048576L; } }
        public long DatMaxBytes { get { return (long)DatMaxMb * 1048576L; } }

        public static List<string> Words(string s) {
            List<string> l = new List<string>();
            foreach (string w in (s ?? "").Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)) l.Add(w);
            return l;
        }

        // Current value of a key in settings.ini notation, null = unknown key.
        public string Get(string key) {
            SettingDef d = SettingDefs.Find(key);
            return d == null ? null : d.Get(this);
        }

        // Sets a key from settings.ini notation. Returns an error text, or null when the value was taken.
        // A rejected value leaves the setting unchanged.
        public string TrySet(string key, string value) {
            SettingDef d = SettingDefs.Find(key);
            if (d == null) return "unknown setting: " + key;
            return d.Set(this, value ?? "");
        }

        // One layer of the loader. Problems become warnings; the previous value is kept.
        public void ApplyLayer(string key, string value, string origin) {
            SettingDef d = SettingDefs.Find(key);
            if (d == null) { Warnings.Add("unknown setting ignored (" + origin + "): " + key); return; }
            string before = d.Get(this);
            string err = d.Set(this, value ?? "");
            if (err != null) { Warnings.Add("invalid value for " + d.Key + " in " + origin + " (" + value + "): " + err + " ; " + before + " is used"); return; }
            Origin[d.Key] = origin;
        }

        public List<string> PcKeys() {
            List<string> l = new List<string>();
            foreach (SettingDef d in SettingDefs.All) { string o; if (Origin.TryGetValue(d.Key, out o) && o == FromPc) l.Add(d.Key); }
            return l;
        }

        // One line for the console and the report : where the values came from.
        public string Describe() {
            List<string> pc = PcKeys();
            string s = SourcePath == "(defaults)" ? "built-in defaults" : SourcePath;
            if (pc.Count == 0) return s;
            return s + " + " + FromPc + " " + pc.Count + " (" + string.Join(", ", pc.ToArray()) + ")";
        }
    }

    // One "KEY=value" line of settings.ini with its section and the comment lines above it.
    public sealed class IniItem {
        public string Section = "", Key = "", Value = "";
        public readonly List<string> Help = new List<string>();
    }

    // Minimal ini reader : KEY=value, lines starting with ; or # are comments,
    // [section] lines are only for readability. UTF-8 (with or without BOM).
    public static class IniFile {
        public static Dictionary<string, string> Read(string path) {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (IniItem it in ReadDoc(path)) d[it.Key] = it.Value;
            return d;
        }

        // Keys in file order, with the section and the comment lines directly above each key.
        public static List<IniItem> ReadDoc(string path) {
            List<IniItem> r = new List<IniItem>();
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return r;
            string section = "";
            List<string> help = new List<string>();
            foreach (string raw in File.ReadAllLines(path, new UTF8Encoding(false))) {
                string line = raw.Trim().TrimStart('﻿');
                if (line.Length == 0) { help.Clear(); continue; }
                if (line[0] == '[') { section = line.Trim('[', ']').Trim(); help.Clear(); continue; }
                if (line[0] == ';' || line[0] == '#') { help.Add(line.TrimStart(';', '#').Trim()); continue; }
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                IniItem it = new IniItem();
                it.Section = section; it.Key = line.Substring(0, eq).Trim(); it.Value = line.Substring(eq + 1).Trim();
                it.Help.AddRange(help); help.Clear();
                r.Add(it);
            }
            return r;
        }
    }
}
