using System;
using System.IO;
using System.Text.RegularExpressions;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Sections {
    // Conservative provenance gate for file tokens. It does not delete extracted data;
    // it decides whether a token is strong enough to become an unresolved EXTFILE edge.
    public static class TokenProvenance {
        static readonly Regex TemplateExpr = new Regex(@"(\{\{|\{%|\{#|<%|%>|\$\{|\burl_for\s*\()", RegexOptions.IgnoreCase);
        static readonly Regex Scheme = new Regex(@"^[a-z][a-z0-9+.-]*:", RegexOptions.IgnoreCase);
        static readonly Regex BareWord = new Regex(@"^[A-Za-z_][A-Za-z0-9_-]*$");

        public static bool ShouldCreateExternalEdge(FileEntry source, string token, string leaf, string context, string bestContext, out string reason) {
            reason = "literal-or-path-like";
            string t = (token ?? "").Trim();
            string l = (leaf ?? "").Trim();
            string ctx = (context ?? "").Trim();
            string best = (bestContext ?? "").Trim();

            if (t.Length == 0 || l.Length == 0) { reason = "empty"; return false; }
            if (TemplateExpr.IsMatch(t)) { reason = "template-expression"; return false; }
            if (Scheme.IsMatch(t) && !t.StartsWith("file:", StringComparison.OrdinalIgnoreCase)) { reason = "url-or-uri"; return false; }
            if (best.Equals("attr", StringComparison.OrdinalIgnoreCase)) { reason = "attribute-like"; return false; }

            bool htmlLike = source != null &&
                (source.Ext.Equals(".html", StringComparison.OrdinalIgnoreCase) ||
                 source.Ext.Equals(".htm", StringComparison.OrdinalIgnoreCase) ||
                 source.Ext.Equals(".jinja", StringComparison.OrdinalIgnoreCase) ||
                 source.Ext.Equals(".jinja2", StringComparison.OrdinalIgnoreCase) ||
                 source.Ext.Equals(".j2", StringComparison.OrdinalIgnoreCase) ||
                 source.Ext.Equals(".cshtml", StringComparison.OrdinalIgnoreCase));

            bool hasSeparator = t.IndexOf('/') >= 0 || t.IndexOf('\\') >= 0;
            bool hasExtension = Path.GetExtension(l).Length > 1;
            bool wildcard = t.IndexOf('*') >= 0 || t.IndexOf('?') >= 0;
            bool ioEvidence = best.Equals("io", StringComparison.OrdinalIgnoreCase) ||
                              best.Equals("write-io", StringComparison.OrdinalIgnoreCase) ||
                              ctx.IndexOf("file", StringComparison.OrdinalIgnoreCase) >= 0 ||
                              ctx.IndexOf("path", StringComparison.OrdinalIgnoreCase) >= 0;

            // HTML attributes often contain route names, CSS classes, template variables, or
            // fragments. A bare word without an extension/path is retained in the report but
            // must not be promoted to an actionable missing-file edge.
            if (htmlLike && BareWord.IsMatch(t) && !hasExtension && !hasSeparator && !wildcard && !ioEvidence) {
                reason = "html-bare-word";
                return false;
            }
            return true;
        }
    }
}
