using System;
using System.Collections.Generic;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [16-3a] HTTP WRAPPER FUNCTIONS
    public sealed class HttpWrapperSection : IReportSection {
        public void Write(ScanContext c) {
            LinkState k = c.Link;
            c.L("---- [16-3a] HTTP WRAPPER FUNCTIONS (functions that call fetch / axios / requests ... directly or via another wrapper) ----");
            c.L(" Depth       = 0 direct http call / N = calls a depth N-1 wrapper (max WRAPDEPTH=" + c.Settings.WrapDepth + ")");
            c.L(" MethodParam = index of the parameter that carries the HTTP method (-1 = none, self/cls not counted)");
            c.L(" Default     = method used when the caller does not give one (from parameter default, method: literal, verb call, fetch)");
            List<string[]> rows = new List<string[]>();
            foreach (Wrap w in k.WrapAll) {
                if (!w.Http) continue;
                string df = string.IsNullOrEmpty(w.Def) ? "-" : w.Def;
                Wrap used;
                string u = k.Wraps.TryGetValue(w.Lang + "|" + w.Name, out used) && ReferenceEquals(used, w) ? "yes" : "no";
                rows.Add(new string[] { w.File, k.FP(w.File), w.Lang, w.Name, w.Depth.ToString(), w.MIdx.ToString(), df, w.DefBasis, w.Via, w.Loc, u });
            }
            if (rows.Count == 0) c.L("(no http wrapper found)");
            c.Report.Tsv("http_wrappers", new string[] { "No", "Path", "Lang", "Function", "Depth", "MethodParam", "DefaultHint", "DefaultBasis", "Via", "Loc", "UsedForResolve" }, rows);
            c.L();
        }
    }

    // [16-3] CLIENT CALLS (url + method) -> matched server route
    public sealed class ClientCallSection : IReportSection {
        sealed class Scored { public RouteInfo H; public int Score; }

        public void Write(ScanContext c) {
            LinkState k = c.Link;
            DepState d = c.Dep;
            c.L("---- [16-3] CLIENT CALLS (url literal + HTTP method) -> matched server route ----");
            c.L(" Method basis : option (method:/type: in call args) / callee-verb (x.get / x.post ...) /");
            c.L("                wrapper-arg(f) (method argument of wrapper f) / wrapper-default(f) / fetch-default / unknown");
            c.L(" Method strength: explicit / inferred / default-hint / rejected-default-hint / unknown");
            c.L(" A conflicting default-hint is kept in MethodHint but is not forced onto the route.");
            c.L(" Url \"{}\"     : dynamic segment (\"/a/\" + id, template ${..}) -> matches only routes with a parameter there");
            c.L(" Evidence     : match = selected route after method + specificity ranking");
            c.L("                candidate = method differs or multiple routes remain equally specific");
            c.L(" \"(no route found)\" = static resource, external api, or route not in the scanned folder.");
            c.L(" Specificity  : exact/static route > fewer parameters > more literal text; all alternatives are kept in http_route_candidates.");
            List<string[]> rows = d.ClientRows;
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                if (!k.Sem.TryGetValue(x.No, out sm) || sm.Raw == null || sm.Raw.Count == 0) continue;
                string self = x.No.ToString();
                foreach (string[] r in SemTool.ResolveCalls(sm.Raw, k.Wraps, sm.Lang)) Call(c, x, self, r, rows);
            }
            if (rows.Count == 0) c.L("(no client url found)");
            c.Report.Tsv("client_calls", new string[] { "No", "Path", "Url", "Hits", "FirstLoc", "MatchedRoute", "Handler", "ServerNo", "ServerPath", "Method", "MethodBasis", "MethodStrength", "MethodHint", "Callee", "Dynamic", "Evidence", "Specificity", "SuppressedAlternatives" }, rows);
            c.L();
            c.L("[route candidate audit : every path/method-compatible candidate before specificity selection; nothing discarded]");
            if (d.RouteAudit.Count == 0) c.L("(none)");
            c.Report.Tsv("http_route_candidates", new string[] { "ClientNo", "ClientPath", "EffectiveMethod", "MethodHint", "MethodStrength", "Url", "Specificity", "Selected", "ServerNo", "ServerPath", "RouteMethod", "Route", "Handler", "MethodBasis" }, d.RouteAudit);
            c.L();
        }

        static string Strength(string bas, string meth) {
            if (bas == "option" || bas == "callee-verb" || bas == "wrapper-arg") return "explicit";
            if (bas.StartsWith("wrapper-arg(", StringComparison.OrdinalIgnoreCase)) return "explicit";
            if (bas.StartsWith("wrapper-default(", StringComparison.OrdinalIgnoreCase) || bas == "fetch-default") return "default-hint";
            if (meth.Length > 0) return "inferred";
            return "unknown";
        }

        static bool MethodListed(string routeMethod, string meth) {
            foreach (string m in (routeMethod ?? "").ToUpperInvariant().Split(',')) if (string.Equals(m.Trim(), meth, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        void Call(ScanContext c, FileEntry x, string self, string[] r, List<string[]> rows) {
            LinkState k = c.Link;
            DepState d = c.Dep;
            string url = r[0], meth = r[1], bas = r[2], cal = r[3], dyn = r[4];
            string methodHint = meth;
            string strength = Strength(bas, meth);
            string mshow = meth.Length > 0 ? meth : "?";
            List<RouteInfo> hitP = new List<RouteInfo>();
            foreach (RouteInfo h in d.Routes) if (SemTool.RouteMatch(h.Path, url)) hitP.Add(h);
            if (hitP.Count == 0) {
                rows.Add(new string[] { self, x.Display, url, r[5], r[6], "(no route found)", "-", "-", "-", mshow, bas, strength, methodHint, cal, dyn, "-", "-", "" });
                return;
            }
            List<RouteInfo> pool = hitP; string ev = "match", note = "";
            if (meth.Length > 0) {
                List<RouteInfo> hitM = new List<RouteInfo>();
                foreach (RouteInfo h in hitP) if (MethodListed(h.Method, meth)) hitM.Add(h);
                if (hitM.Count > 0) pool = hitM;
                else if (strength == "default-hint") { meth = ""; mshow = "?"; strength = "rejected-default-hint"; note = " (default hint conflicts; route-selected)"; }
                else { ev = "candidate"; note = " (method differs)"; }
            }
            List<Scored> scored = new List<Scored>();
            int bestScore = int.MinValue;
            foreach (RouteInfo h in pool) {
                Scored z = new Scored(); z.H = h; z.Score = SemTool.RouteSpecificity(h.Path, url);
                scored.Add(z);
                if (z.Score > bestScore) bestScore = z.Score;
            }
            List<Scored> best = new List<Scored>();
            foreach (Scored z in scored) if (z.Score == bestScore) best.Add(z);
            if (best.Count > 1) { ev = "candidate"; if (note.Length == 0) note = " (equal specificity)"; }
            foreach (Scored z in scored)
                d.RouteAudit.Add(new string[] { self, x.Display, mshow, methodHint, strength, url, z.Score.ToString(), z.Score == bestScore ? "yes" : "no", z.H.No.ToString(), k.FP(z.H.No), z.H.Method, z.H.Path, z.H.Handler, bas });
            string alt = (scored.Count - 1).ToString();
            foreach (Scored z in best) {
                RouteInfo h = z.H;
                rows.Add(new string[] { self, x.Display, url, r[5], r[6], h.Method + " " + h.Path + note, h.Handler, h.No.ToString(), k.FP(h.No), mshow, bas, strength, methodHint, cal, dyn, ev, z.Score.ToString(), alt });
                d.Edges.Add("HTTP", self, h.No.ToString(), mshow + " " + url + " => " + h.Method + " " + h.Path + " (" + h.Handler + ")" + note +
                    " [" + bas + "; method-strength=" + strength + "; method-hint=" + methodHint + "; specificity=" + z.Score + "; alternatives=" + alt + "]", r[6], ev);
            }
        }
    }
}
