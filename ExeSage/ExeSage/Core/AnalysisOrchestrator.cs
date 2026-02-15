using ExeSage.Features;
using ExeSage.PE;
using ExeSage.Scoring;
using System;

namespace ExeSage.Core;

/// <summary>
/// Coordinates the analysis pipeline: parse → analyze features → score.
/// Each stage after PE parsing is optional — failures are logged and skipped.
/// </summary>
internal class AnalysisOrchestrator {
    public ExecutableMetadata Analyze(string filePath) {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentNullException(nameof(filePath), "File path cannot be null or empty");

        var metadata = new ExecutableMetadata(filePath);

        // PE parsing is critical — if this fails, nothing else works
        var peParser = new PeParser();
        peParser.Parse(metadata);

        // Feature extraction — each stage is independent
        RunSafe(() => new SignatureAnalyzer().Analyze(metadata), "Signature analysis", () => {
            metadata.IsSigned = false;
            metadata.IsSignatureValid = false;
        });

        RunSafe(() => new EntropyAnalyzer().Analyze(metadata), "Entropy analysis");
        RunSafe(() => new ImportAnalyzer().Analyze(metadata), "Import analysis");
        RunSafe(() => new StringAnalyzer().Analyze(metadata), "String analysis");
        RunSafe(() => new PeAnomalyAnalyzer().Analyze(metadata), "PE anomaly detection");

        // Scoring depends on all features above
        RunSafe(() => new RiskScorer().Calculate(metadata), "Risk scoring", () => {
            metadata.RiskScore = 0;
            metadata.RiskLevel = "Unknown";
        });

        return metadata;
    }

    private void RunSafe(Action action, string stageName, Action fallback = null) {
        try {
            action();
        }
        catch (Exception ex) {
            LogWarning($"{stageName} failed: {ex.Message}");
            fallback?.Invoke();
        }
    }

    private void LogWarning(string message) {
        var originalColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[WARNING] {message}");
        Console.ForegroundColor = originalColor;
    }
}
