using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace FolderScan.Core {
    // All tunable values of a scan. Defaults are the values of folderscan v5.18.
    // Values are read from settings.ini (KEY=value); unknown keys are ignored,
    // missing keys keep their default.
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

        public string SourcePath = "(defaults)";
        public string Home = "";     // folder of folderscan.bat (templates\ is read from here)
        public readonly List<string> Warnings = new List<string>();

        public long LinkMaxBytes { get { return (long)LinkMaxMb * 1048576L; } }
        public long DatMaxBytes { get { return (long)DatMaxMb * 1048576L; } }

        static List<string> Words(string s) {
            List<string> l = new List<string>();
            foreach (string w in s.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)) l.Add(w);
            return l;
        }

        public static Settings Load(string path) {
            Settings s = new Settings();
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) {
                s.Warnings.Add("settings file not found, defaults are used: " + path);
                return s;
            }
            s.SourcePath = path;
            Dictionary<string, string> kv = IniFile.Read(path);
            foreach (KeyValuePair<string, string> p in kv) s.Apply(p.Key, p.Value);
            for (int i = 0; i < s.GenericKeys.Count; i++) s.GenericKeys[i] = s.GenericKeys[i].ToLowerInvariant();
            return s;
        }

        void Apply(string key, string value) {
            switch (key.ToUpperInvariant()) {
                case "DIAG": Diag = Int(key, value, Diag); break;
                case "MAP": Map = Int(key, value, Map); break;
                case "DUMPDAT": DumpDat = Int(key, value, DumpDat); break;
                case "DUMPTEXT": DumpText = Int(key, value, DumpText); break;
                case "DUMPFILES": DumpFiles = new List<string>(); foreach (string p in value.Split(';')) if (p.Trim().Length > 0) DumpFiles.Add(p.Trim()); break;
                case "DIAGTOP": DiagTop = Int(key, value, DiagTop); break;
                case "OPENRESULT": OpenResult = Int(key, value, OpenResult); break;
                case "MAXCAB": MaxCab = Int(key, value, MaxCab); break;
                case "CABEXT": CabExt = Int(key, value, CabExt); break;
                case "HEADBYTES": HeadBytes = Int(key, value, HeadBytes); break;
                case "HEXMAX": HexMax = Int(key, value, HexMax); break;
                case "DATINCAB": DatInCab = Int(key, value, DatInCab); break;
                case "DATMAXMB": DatMaxMb = Int(key, value, DatMaxMb); break;
                case "RECSAMPLE": RecSample = Int(key, value, RecSample); break;
                case "RECLAG": RecLag = Int(key, value, RecLag); break;
                case "HASHALL": HashAll = Int(key, value, HashAll); break;
                case "MINSTR": MinStr = Int(key, value, MinStr); break;
                case "LINKMAXMB": LinkMaxMb = Int(key, value, LinkMaxMb); break;
                case "KEYMAX": KeyMax = Int(key, value, KeyMax); break;
                case "KEYMAXFILES": KeyMaxFiles = Int(key, value, KeyMaxFiles); break;
                case "KEYTOP": KeyTop = Int(key, value, KeyTop); break;
                case "PROFREC": ProfRec = Int(key, value, ProfRec); break;
                case "RECMIN": RecMin = Dbl(key, value, RecMin); break;
                case "SKIPEXT": SkipExt = Words(value); break;
                case "RECEXT": RecExt = Words(value); break;
                case "SYMMIN": SymMin = Int(key, value, SymMin); break;
                case "MERMAIDKEY": MermaidKey = Int(key, value, MermaidKey); break;
                case "MERMAIDSYM": MermaidSym = Int(key, value, MermaidSym); break;
                case "MERMAIDWEAK": MermaidWeak = Int(key, value, MermaidWeak); break;
                case "GENERICKEYS": GenericKeys = Words(value); break;
                case "WRAPDEPTH": WrapDepth = Int(key, value, WrapDepth); break;
                case "REVIEWMAX": ReviewMax = Int(key, value, ReviewMax); break;
                case "SNIPLEN": SnipLen = Int(key, value, SnipLen); break;
                case "GAPMAX": GapMax = Int(key, value, GapMax); break;
                case "GAPCTX": GapCtx = Int(key, value, GapCtx); break;
                case "HISTORY": History = Int(key, value, History); break;
                default: Warnings.Add("unknown setting ignored: " + key); break;
            }
        }

        int Int(string key, string v, int def) {
            int r;
            if (int.TryParse(v.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out r)) return r;
            Warnings.Add("invalid number for " + key + " (" + v + "), default " + def + " is used");
            return def;
        }

        double Dbl(string key, string v, double def) {
            double r;
            if (double.TryParse(v.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out r)) return r;
            Warnings.Add("invalid number for " + key + " (" + v + "), default " + def + " is used");
            return def;
        }
    }

    // Minimal ini reader : KEY=value, lines starting with ; or # are comments,
    // [section] lines are only for readability. UTF-8 (with or without BOM).
    public static class IniFile {
        public static Dictionary<string, string> Read(string path) {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string raw in File.ReadAllLines(path, new UTF8Encoding(false))) {
                string line = raw.Trim();
                if (line.Length == 0 || line[0] == ';' || line[0] == '#' || line[0] == '[') continue;
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                d[line.Substring(0, eq).Trim()] = line.Substring(eq + 1).Trim();
            }
            return d;
        }
    }
}
