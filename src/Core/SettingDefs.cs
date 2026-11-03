using System;
using System.Collections.Generic;
using System.Globalization;

namespace FolderScan.Core {
    // How one key of settings.ini is read from / written to Settings.
    // Set returns an error text, or null when the value was taken (the field is only changed on success).
    public sealed class SettingDef {
        public readonly string Key;
        readonly Func<Settings, string> get;
        readonly Func<Settings, string, string> set;

        public SettingDef(string key, Func<Settings, string> get, Func<Settings, string, string> set) {
            Key = key; this.get = get; this.set = set;
        }

        public string Get(Settings s) { return get(s); }
        public string Set(Settings s, string value) { return set(s, value); }
    }

    // Every key of settings.ini. To add a setting : add the field to Settings and one line here.
    public static class SettingDefs {
        public static readonly List<SettingDef> All = new List<SettingDef> {
            Flag("OPENRESULT", s => s.OpenResult, (s, v) => s.OpenResult = v),
            Flag("DIAG", s => s.Diag, (s, v) => s.Diag = v),
            Int("DIAGTOP", 0, s => s.DiagTop, (s, v) => s.DiagTop = v),
            Flag("MAP", s => s.Map, (s, v) => s.Map = v),
            Flag("DUMPDAT", s => s.DumpDat, (s, v) => s.DumpDat = v),
            Flag("DUMPTEXT", s => s.DumpText, (s, v) => s.DumpText = v),
            List("DUMPFILES", ';', s => s.DumpFiles, (s, v) => s.DumpFiles = v),
            Int("MAXCAB", 0, s => s.MaxCab, (s, v) => s.MaxCab = v),
            Int("CABEXT", 0, s => s.CabExt, (s, v) => s.CabExt = v),
            Int("HEADBYTES", 0, s => s.HeadBytes, (s, v) => s.HeadBytes = v),
            Int("HEXMAX", 0, s => s.HexMax, (s, v) => s.HexMax = v),
            Flag("DATINCAB", s => s.DatInCab, (s, v) => s.DatInCab = v),
            Int("DATMAXMB", 0, s => s.DatMaxMb, (s, v) => s.DatMaxMb = v),
            Int("RECSAMPLE", 1, s => s.RecSample, (s, v) => s.RecSample = v),
            Int("RECLAG", 1, s => s.RecLag, (s, v) => s.RecLag = v),
            Flag("HASHALL", s => s.HashAll, (s, v) => s.HashAll = v),
            Int("MINSTR", 1, s => s.MinStr, (s, v) => s.MinStr = v),
            Int("LINKMAXMB", 0, s => s.LinkMaxMb, (s, v) => s.LinkMaxMb = v),
            Int("KEYMAX", 0, s => s.KeyMax, (s, v) => s.KeyMax = v),
            Int("KEYMAXFILES", 0, s => s.KeyMaxFiles, (s, v) => s.KeyMaxFiles = v),
            Int("KEYTOP", 0, s => s.KeyTop, (s, v) => s.KeyTop = v),
            Int("PROFREC", 1, s => s.ProfRec, (s, v) => s.ProfRec = v),
            Dbl("RECMIN", s => s.RecMin, (s, v) => s.RecMin = v),
            List("SKIPEXT", ' ', s => s.SkipExt, (s, v) => s.SkipExt = v),
            List("RECEXT", ' ', s => s.RecExt, (s, v) => s.RecExt = v),
            Int("SYMMIN", 1, s => s.SymMin, (s, v) => s.SymMin = v),
            Flag("MERMAIDKEY", s => s.MermaidKey, (s, v) => s.MermaidKey = v),
            Flag("MERMAIDSYM", s => s.MermaidSym, (s, v) => s.MermaidSym = v),
            Flag("MERMAIDWEAK", s => s.MermaidWeak, (s, v) => s.MermaidWeak = v),
            List("GENERICKEYS", ' ', s => s.GenericKeys, (s, v) => { for (int i = 0; i < v.Count; i++) v[i] = v[i].ToLowerInvariant(); s.GenericKeys = v; }),
            Int("WRAPDEPTH", 0, s => s.WrapDepth, (s, v) => s.WrapDepth = v),
            Int("REVIEWMAX", 0, s => s.ReviewMax, (s, v) => s.ReviewMax = v),
            Int("SNIPLEN", 1, s => s.SnipLen, (s, v) => s.SnipLen = v),
            Int("GAPMAX", 0, s => s.GapMax, (s, v) => s.GapMax = v),
            Int("GAPCTX", 0, s => s.GapCtx, (s, v) => s.GapCtx = v),
            Flag("HISTORY", s => s.History, (s, v) => s.History = v),
        };

        static readonly Dictionary<string, SettingDef> byKey = Index();

        static Dictionary<string, SettingDef> Index() {
            Dictionary<string, SettingDef> d = new Dictionary<string, SettingDef>(StringComparer.OrdinalIgnoreCase);
            foreach (SettingDef x in All) d[x.Key] = x;
            return d;
        }

        public static SettingDef Find(string key) {
            SettingDef d;
            return key != null && byKey.TryGetValue(key.Trim(), out d) ? d : null;
        }

        static string Inv(int v) { return v.ToString(CultureInfo.InvariantCulture); }

        static SettingDef Int(string key, int min, Func<Settings, int> get, Action<Settings, int> set) {
            return new SettingDef(key, s => Inv(get(s)), (s, v) => {
                int r;
                if (!int.TryParse(v.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out r)) return "a whole number is expected";
                if (r < min) return "the smallest value is " + Inv(min);
                set(s, r);
                return null;
            });
        }

        static SettingDef Flag(string key, Func<Settings, int> get, Action<Settings, int> set) {
            return new SettingDef(key, s => Inv(get(s)), (s, v) => {
                string t = v.Trim();
                if (t != "0" && t != "1") return "0 or 1 is expected";
                set(s, t == "1" ? 1 : 0);
                return null;
            });
        }

        static SettingDef Dbl(string key, Func<Settings, double> get, Action<Settings, double> set) {
            return new SettingDef(key, s => get(s).ToString("0.###", CultureInfo.InvariantCulture), (s, v) => {
                double r;
                if (!double.TryParse(v.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out r)) return "a number is expected";
                set(s, r);
                return null;
            });
        }

        // sep ' ' = space separated words, ';' = ; separated entries (may contain spaces)
        static SettingDef List(string key, char sep, Func<Settings, List<string>> get, Action<Settings, List<string>> set) {
            return new SettingDef(key, s => string.Join(sep == ' ' ? " " : ";", get(s).ToArray()), (s, v) => {
                List<string> l = new List<string>();
                if (sep == ' ') l = Settings.Words(v);
                else foreach (string p in v.Split(sep)) if (p.Trim().Length > 0) l.Add(p.Trim());
                set(s, l);
                return null;
            });
        }
    }
}
