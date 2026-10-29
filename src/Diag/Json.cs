using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace FolderScan.Diag {
    // Minimal JSON writer (no external library; .NET Framework 4.x only).
    // Values : string, bool, int/long/double, null, IDictionary (object), IEnumerable (array), JsonObj.
    public sealed class JsonObj : IEnumerable {
        readonly List<KeyValuePair<string, object>> items = new List<KeyValuePair<string, object>>();
        public JsonObj Add(string key, object value) { items.Add(new KeyValuePair<string, object>(key, value)); return this; }
        public IEnumerator GetEnumerator() { return items.GetEnumerator(); }
        public List<KeyValuePair<string, object>> Items { get { return items; } }
    }

    public static class Json {
        public static string Write(object v) { StringBuilder sb = new StringBuilder(); Value(sb, v, 0); sb.Append("\r\n"); return sb.ToString(); }

        static void Indent(StringBuilder sb, int n) { sb.Append("\r\n"); sb.Append(' ', n * 2); }

        static void Value(StringBuilder sb, object v, int lv) {
            if (v == null) { sb.Append("null"); return; }
            if (v is string) { Str(sb, (string)v); return; }
            if (v is bool) { sb.Append((bool)v ? "true" : "false"); return; }
            if (v is int || v is long) { sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); return; }
            if (v is double) { sb.Append(((double)v).ToString("0.###", CultureInfo.InvariantCulture)); return; }
            JsonObj o = v as JsonObj;
            if (o != null) {
                if (o.Items.Count == 0) { sb.Append("{}"); return; }
                sb.Append('{');
                for (int i = 0; i < o.Items.Count; i++) {
                    if (i > 0) sb.Append(',');
                    Indent(sb, lv + 1); Str(sb, o.Items[i].Key); sb.Append(": "); Value(sb, o.Items[i].Value, lv + 1);
                }
                Indent(sb, lv); sb.Append('}');
                return;
            }
            IDictionary d = v as IDictionary;
            if (d != null) { JsonObj t = new JsonObj(); foreach (DictionaryEntry e in d) t.Add(Convert.ToString(e.Key), e.Value); Value(sb, t, lv); return; }
            IEnumerable en = v as IEnumerable;
            if (en != null) {
                List<object> l = new List<object>(); foreach (object x in en) l.Add(x);
                if (l.Count == 0) { sb.Append("[]"); return; }
                bool simple = true; foreach (object x in l) if (x is JsonObj || x is IDictionary || (x is IEnumerable && !(x is string))) { simple = false; break; }
                sb.Append('[');
                for (int i = 0; i < l.Count; i++) {
                    if (i > 0) sb.Append(simple ? ", " : ",");
                    if (!simple) Indent(sb, lv + 1);
                    Value(sb, l[i], lv + 1);
                }
                if (!simple) Indent(sb, lv);
                sb.Append(']');
                return;
            }
            Str(sb, Convert.ToString(v, CultureInfo.InvariantCulture));
        }

        static void Str(StringBuilder sb, string s) {
            sb.Append('"');
            foreach (char ch in s) {
                switch (ch) {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (ch < 0x20) sb.Append("\\u").Append(((int)ch).ToString("x4"));
                        else sb.Append(ch);
                        break;
                }
            }
            sb.Append('"');
        }

        // Minimal JSON reader : object -> Dictionary<string, object>, array -> List<object>,
        // number -> double, string, bool, null. Throws FormatException on bad input.
        public static object Parse(string s) { int i = 0; object v = Read(s, ref i); Ws(s, ref i); if (i != s.Length) throw new FormatException("trailing data"); return v; }

        static void Ws(string s, ref int i) { while (i < s.Length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n' || s[i] == '\uFEFF')) i++; }

        static object Read(string s, ref int i) {
            Ws(s, ref i);
            if (i >= s.Length) throw new FormatException("unexpected end");
            char c = s[i];
            if (c == '{') {
                Dictionary<string, object> d = new Dictionary<string, object>(StringComparer.Ordinal); i++;
                Ws(s, ref i); if (s[i] == '}') { i++; return d; }
                while (true) {
                    Ws(s, ref i); string k = ReadStr(s, ref i); Ws(s, ref i);
                    if (s[i] != ':') throw new FormatException("':' expected"); i++;
                    d[k] = Read(s, ref i); Ws(s, ref i);
                    if (s[i] == ',') { i++; continue; }
                    if (s[i] == '}') { i++; return d; }
                    throw new FormatException("',' or '}' expected");
                }
            }
            if (c == '[') {
                List<object> l = new List<object>(); i++;
                Ws(s, ref i); if (s[i] == ']') { i++; return l; }
                while (true) {
                    l.Add(Read(s, ref i)); Ws(s, ref i);
                    if (s[i] == ',') { i++; continue; }
                    if (s[i] == ']') { i++; return l; }
                    throw new FormatException("',' or ']' expected");
                }
            }
            if (c == '"') return ReadStr(s, ref i);
            if (At(s, i, "true")) { i += 4; return true; }
            if (At(s, i, "false")) { i += 5; return false; }
            if (At(s, i, "null")) { i += 4; return null; }
            int st = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            if (st == i) throw new FormatException("bad value at " + i);
            return double.Parse(s.Substring(st, i - st), CultureInfo.InvariantCulture);
        }

        static bool At(string s, int i, string w) { return i + w.Length <= s.Length && string.CompareOrdinal(s, i, w, 0, w.Length) == 0; }

        static string ReadStr(string s, ref int i) {
            if (s[i] != '"') throw new FormatException("string expected");
            i++;
            StringBuilder sb = new StringBuilder();
            while (s[i] != '"') {
                char ch = s[i++];
                if (ch != '\\') { sb.Append(ch); continue; }
                char e = s[i++];
                switch (e) {
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u': sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber)); i += 4; break;
                    default: sb.Append(e); break;
                }
            }
            i++;
            return sb.ToString();
        }

        // helpers for reading parsed values
        public static string S(object o, string key) { Dictionary<string, object> d = o as Dictionary<string, object>; object v; return d != null && d.TryGetValue(key, out v) && v != null ? Convert.ToString(v, CultureInfo.InvariantCulture) : ""; }
        public static int I(object o, string key) { Dictionary<string, object> d = o as Dictionary<string, object>; object v; return d != null && d.TryGetValue(key, out v) && v is double ? (int)(double)v : 0; }
        public static object O(object o, string key) { Dictionary<string, object> d = o as Dictionary<string, object>; object v; return d != null && d.TryGetValue(key, out v) ? v : null; }
        public static List<object> A(object o, string key) { return O(o, key) as List<object> ?? new List<object>(); }
    }
}
