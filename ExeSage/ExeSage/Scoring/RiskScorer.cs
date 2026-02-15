using System;
using System.Collections.Generic;
using System.Linq;
using ExeSage.Core;

namespace ExeSage.Scoring;

/// <summary>
/// Weighted risk scoring (0–100) with context awareness and signal amplification.
///
/// Key design decisions:
/// - Penalties scale with count (3 injection APIs > 1 injection API)
/// - Multiple suspicious categories together trigger a combination multiplier
/// - .NET binaries get a baseline bump because import analysis can't see CLR calls
/// - Valid signatures significantly reduce all penalties
///
/// Score bands:
///   0–20  VeryLow  |  21–40 Low  |  41–60 Medium  |  61–80 High  |  81–100 Critical
/// </summary>
internal class RiskScorer {
    private const double HIGH_ENTROPY_THRESHOLD = 7.0;

    public void Calculate(ExecutableMetadata metadata) {
        if (metadata == null) throw new ArgumentNullException(nameof(metadata));

        bool trusted = metadata.IsSigned && metadata.IsSignatureValid;
        double score = 0.0;

        score += ScoreSignature(metadata);
        score += ScoreEntropy(metadata, trusted);

        double importScore = ScoreImports(metadata, trusted);
        double stringScore = ScoreStrings(metadata, trusted);
        double anomalyScore = ScorePeAnomalies(metadata, trusted);
        double dotnetScore = ScoreDotNet(metadata, trusted);

        score += importScore + stringScore + anomalyScore + dotnetScore;

        // Signal combination multiplier: when multiple high-signal categories
        // fire together, the binary is more suspicious than any single signal suggests.
        // E.g., network + crypto + anti-debug + unsigned = almost certainly malicious.
        int highSignalCategories = CountHighSignalCategories(metadata);
        if (highSignalCategories >= 3) {
            double bonus = (highSignalCategories - 2) * 8.0;
            if (trusted) bonus *= 0.3;
            score += bonus;
        }

        metadata.RiskScore = Math.Clamp(score, 0, 100);
        metadata.RiskLevel = metadata.RiskScore switch {
            <= 20 => "VeryLow",
            <= 40 => "Low",
            <= 60 => "Medium",
            <= 80 => "High",
            _ => "Critical"
        };
    }

    /// <summary>
    /// Counts distinct high-signal categories present in the analysis.
    /// Used for combination multiplier — benign software rarely triggers 3+.
    /// </summary>
    private int CountHighSignalCategories(ExecutableMetadata m) {
        int count = 0;
        var importCats = m.SuspiciousImports?.Select(i => i.Category).Distinct().ToHashSet() ?? new HashSet<string>();

        if (importCats.Contains("ProcessInjection")) count++;
        if (importCats.Contains("AntiDebug")) count++;
        if (importCats.Contains("Network")) count++;
        if (importCats.Contains("Cryptography")) count++;
        if (importCats.Contains("PersistenceService")) count++;
        if (importCats.Contains("MemoryManipulation")) count++;

        var stringCats = m.SuspiciousStrings?.Select(s => s.Category).Distinct().ToHashSet() ?? new HashSet<string>();
        if (stringCats.Contains("SandboxDetection")) count++;
        if (stringCats.Contains("IpAddress")) count++;
        if (stringCats.Contains("Base64")) count++;
        if (stringCats.Contains("ShellExecution")) count++;
        if (stringCats.Contains("CredentialAccess")) count++;

        // .NET capabilities count as import-equivalent signals
        if (stringCats.Contains("DotNetCapability")) {
            int dotnetCapCount = m.SuspiciousStrings.Count(s => s.Category == "DotNetCapability");
            // 3+ .NET capabilities (sockets + process + crypto) = serious
            if (dotnetCapCount >= 3) count += 2;
            else if (dotnetCapCount >= 1) count++;
        }

        return count;
    }

    private double ScoreSignature(ExecutableMetadata m) {
        if (m.IsSigned && m.IsSignatureValid) return -15.0;
        if (m.IsSigned) return 12.0; // Signed but invalid = tampered?
        return 8.0;
    }

    private double ScoreEntropy(ExecutableMetadata m, bool trusted) {
        if (m.Sections == null) return 0;

        double score = 0;
        foreach (var s in m.Sections) {
            if (s.Entropy == 0.0) continue;

            if (s.IsExecutable && s.Entropy > HIGH_ENTROPY_THRESHOLD) {
                // Higher entropy = more suspicious, scale linearly 7.0-8.0 → 8-15 points
                double severity = 8.0 + (s.Entropy - 7.0) * 7.0;
                score += trusted ? severity * 0.4 : severity;
            }

            // Writable + executable section with high entropy = almost certainly packed
            if (s.IsExecutable && s.IsWritable && s.Entropy > 6.5)
                score += 10.0;
        }
        return score;
    }

    private double ScoreImports(ExecutableMetadata m, bool trusted) {
        double score = 0;

        // Very few imports suggests packing (runtime resolution)
        if (m.ImportCount > 0 && m.ImportCount < 10)
            score += trusted ? 3.0 : 10.0;

        if (m.SuspiciousImports == null || m.SuspiciousImports.Count == 0)
            return score;

        var cats = m.SuspiciousImports.GroupBy(i => i.Category)
            .ToDictionary(g => g.Key, g => g.Count());

        // Process injection — scales with count, highly suspicious
        if (cats.TryGetValue("ProcessInjection", out int injCount))
            score += ScaleByCount(injCount, 12.0, 20.0) * (trusted ? 0.3 : 1.0);

        // Memory manipulation (VirtualAlloc, VirtualProtect)
        if (cats.TryGetValue("MemoryManipulation", out int memCount))
            score += ScaleByCount(memCount, 5.0, 12.0) * (trusted ? 0.3 : 1.0);

        // Process execution
        if (cats.TryGetValue("ProcessExecution", out int execCount))
            score += ScaleByCount(execCount, 5.0, 10.0) * (trusted ? 0.2 : 1.0);

        // Anti-debug (strong)
        if (cats.TryGetValue("AntiDebug", out int dbgCount))
            score += ScaleByCount(dbgCount, 10.0, 15.0) * (trusted ? 0.2 : 1.0);

        // Weak anti-debug only scores when combined with strong
        if (cats.ContainsKey("AntiDebugWeak") && cats.ContainsKey("AntiDebug"))
            score += 5.0;

        // Network
        if (cats.TryGetValue("Network", out int netCount))
            score += ScaleByCount(netCount, 8.0, 15.0) * (trusted ? 0.3 : 1.0);

        // Cryptography
        if (cats.TryGetValue("Cryptography", out int cryptCount))
            score += ScaleByCount(cryptCount, 5.0, 10.0) * (trusted ? 0.0 : 1.0);

        // Services
        if (cats.ContainsKey("PersistenceService"))
            score += trusted ? 5.0 : 12.0;

        // Registry — only if Run key strings detected
        bool hasRunKeys = m.SuspiciousStrings?.Any(s =>
            s.Category == "SuspiciousPath" &&
            s.Value.Contains("CurrentVersion\\Run", StringComparison.OrdinalIgnoreCase)) ?? false;

        if (cats.ContainsKey("PersistenceRegistry") && hasRunKeys)
            score += trusted ? 2.0 : 8.0;

        return score;
    }

    /// <summary>
    /// Scales penalty between min and max based on how many APIs were found.
    /// 1 API = min penalty, 4+ APIs = max penalty.
    /// </summary>
    private double ScaleByCount(int count, double min, double max) {
        double t = Math.Clamp((count - 1.0) / 3.0, 0.0, 1.0);
        return min + t * (max - min);
    }

    private double ScoreStrings(ExecutableMetadata m, bool trusted) {
        if (m.SuspiciousStrings == null || m.SuspiciousStrings.Count == 0) return 0;

        double score = 0;
        var cats = m.SuspiciousStrings.GroupBy(s => s.Category)
            .ToDictionary(g => g.Key, g => g.Count());

        if (cats.TryGetValue("Base64", out int b64))
            score += Math.Min(b64 * 3.0, 12.0);

        if (cats.ContainsKey("IpAddress")) score += 12.0;
        if (cats.ContainsKey("Url")) score += trusted ? 4.0 : 10.0;
        if (cats.ContainsKey("SuspiciousPath")) score += 6.0;
        if (cats.ContainsKey("Obfuscated")) score += 8.0;
        if (cats.ContainsKey("SandboxDetection")) score += 15.0;

        // Shell execution is a very strong signal for C2 / RAT behavior
        if (cats.TryGetValue("ShellExecution", out int shellCount))
            score += Math.Min(shellCount * 5.0, 15.0);

        // Credential access keywords
        if (cats.TryGetValue("CredentialAccess", out int credCount))
            score += Math.Min(credCount * 4.0, 12.0);

        return score;
    }

    /// <summary>
    /// .NET binaries hide their capabilities in CLR metadata rather than imports.
    /// DotNetCapability strings (System.Net.Sockets, System.Diagnostics.Process, etc.)
    /// serve as the equivalent of import analysis for managed code.
    /// </summary>
    private double ScoreDotNet(ExecutableMetadata m, bool trusted) {
        if (!m.IsDotNet) return 0;

        double score = 0;

        // Unsigned .NET exe baseline
        if (!trusted)
            score += 5.0;

        // .NET capability scoring — these are the import-equivalents
        var dotnetCaps = m.SuspiciousStrings?
            .Where(s => s.Category == "DotNetCapability")
            .Select(s => s.Value)
            .ToList() ?? new List<string>();

        if (dotnetCaps.Count == 0) return score;

        // Each capability adds points, scaling with count
        score += Math.Min(dotnetCaps.Count * 4.0, 20.0);

        // Specific dangerous combinations in .NET
        bool hasNetwork = dotnetCaps.Any(c => c.Contains("Sockets") || c.Contains("Http"));
        bool hasProcess = dotnetCaps.Any(c => c.Contains("Process"));
        bool hasCrypto = dotnetCaps.Any(c => c.Contains("Cryptography"));
        bool hasReflection = dotnetCaps.Any(c => c.Contains("Reflection"));
        bool hasInterop = dotnetCaps.Any(c => c.Contains("InteropServices"));

        // Network + Process = remote command execution pattern (C2)
        if (hasNetwork && hasProcess)
            score += 10.0;

        // Network + Crypto = encrypted C2 communication
        if (hasNetwork && hasCrypto)
            score += 5.0;

        // Reflection + Interop = dynamic loading / evasion
        if (hasReflection && hasInterop)
            score += 8.0;

        return score;
    }

    private double ScorePeAnomalies(ExecutableMetadata m, bool trusted) {
        if (m.PeAnomalies == null || m.PeAnomalies.Count == 0) return 0;

        double score = 0;
        var grouped = m.PeAnomalies.GroupBy(a => a.Type)
            .ToDictionary(g => g.Key, g => g.ToList());

        if (grouped.TryGetValue("EntryPoint", out var epList))
            score += 10.0 * Math.Min(epList.Count, 2);

        if (grouped.TryGetValue("Section", out var secList))
            score += 8.0 * Math.Min(secList.Count, 3);

        if (grouped.ContainsKey("Timestamp")) score += 8.0;
        if (grouped.ContainsKey("TLS")) score += trusted ? 4.0 : 10.0;
        if (grouped.ContainsKey("Checksum")) score += 5.0;
        if (grouped.ContainsKey("Structure")) score += 4.0;

        return score;
    }
}
