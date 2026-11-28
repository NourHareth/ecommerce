using System.Text.RegularExpressions;

namespace AmCart.ProductService.Api.Observability;

/// <summary>
/// Recognises common injection patterns in request values, for DETECTION only (section 4.7).
/// It protects nothing: the protection is parameterised queries (F1) and output encoding. It answers
/// "is someone probing us?", so it favours few false positives over catching every obfuscated
/// variant. Values are capped and every pattern has a timeout, so a crafted value cannot make the
/// detection itself expensive.
/// </summary>
public static class InjectionIndicators
{
    private const int MaxScannedLength = 1024;
    private const RegexOptions Options =
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(50);

    private static readonly (string Name, Regex Pattern)[] Rules =
    {
        // A quote closing a string literal, then boolean logic with a comparison.
        ("sql-boolean", new Regex(
            @"['""]\s*\)*\s*\b(?:or|and)\b\s+[^=<>]{0,30}?(?:=|<|>|\blike\b|\bnot\b|\btrue\b|\bfalse\b|\bselect\b|\bexists\b|\bsleep\b|\bpg_sleep\b)",
            Options, MatchTimeout)),
        // Always-true comparisons: 1=1, 'a'='a.
        ("sql-tautology", new Regex(@"(?<![\w.])(\d+)\s*=\s*\1(?![\w.])|'(\w*)'\s*=\s*'\2(?!\w)", Options, MatchTimeout)),
        // A comment right after a closed literal, or an inline comment.
        ("sql-comment", new Regex(@"['"")]\s*(?:--|#|/\*)|/\*.*?\*/", Options, MatchTimeout)),
        ("sql-union", new Regex(@"\bunion\b(?:\s|/\*.*?\*/|\()+(?:all\b(?:\s|/\*.*?\*/)+)?select\b", Options, MatchTimeout)),
        ("sql-stacked", new Regex(@";\s*(?:select|insert|update|delete|drop|alter|create|truncate|exec|declare|copy)\b", Options, MatchTimeout)),
        ("sql-delay", new Regex(@"\b(?:pg_sleep|sleep|benchmark)\s*\(|\bwaitfor\s+delay\b", Options, MatchTimeout)),
        ("sql-catalog", new Regex(@"\b(?:information_schema|pg_catalog|pg_shadow|pg_user|sysobjects|sqlite_master)\b", Options, MatchTimeout)),
        ("xss", new Regex(@"<\s*/?\s*(?:script|iframe|svg|img|body|object|embed)\b|\bjavascript\s*:|\bon(?:error|load|mouseover|focus)\s*=", Options, MatchTimeout)),
    };

    /// <summary>Names of the rules the value matches; empty when it looks harmless.</summary>
    public static IReadOnlyList<string> Find(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return Array.Empty<string>();
        if (value.Length > MaxScannedLength)
            value = value[..MaxScannedLength];

        List<string>? found = null;
        foreach (var (name, pattern) in Rules)
        {
            string? hit;
            try
            {
                hit = pattern.IsMatch(value) ? name : null;
            }
            catch (RegexMatchTimeoutException)
            {
                hit = "scan-timeout";   // a value built to be slow to scan is itself suspicious
            }
            if (hit != null)
                (found ??= new List<string>()).Add(hit);
        }
        return found ?? (IReadOnlyList<string>)Array.Empty<string>();
    }
}
