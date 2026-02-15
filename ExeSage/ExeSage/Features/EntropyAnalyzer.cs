using System;
using System.Collections.Generic;
using System.IO;
using ExeSage.Core;

namespace ExeSage.Features;

/// <summary>
/// Calculates Shannon entropy per PE section to detect packing/encryption.
/// Normal code: 5.5–6.5 | Compressed/encrypted: 7.5–8.0
/// </summary>
internal class EntropyAnalyzer {
    private const int CHUNK_SIZE = 8192;

    public void Analyze(ExecutableMetadata metadata) {
        if (metadata == null)
            throw new ArgumentNullException(nameof(metadata));

        if (metadata.Sections == null || metadata.Sections.Count == 0)
            return;

        using var stream = File.OpenRead(metadata.FilePath);

        foreach (var section in metadata.Sections) {
            try {
                section.Entropy = CalculateSectionEntropy(stream, section);
            }
            catch {
                section.Entropy = 0.0;
            }
        }
    }

    private double CalculateSectionEntropy(FileStream stream, SectionMetadata section) {
        if (section.RawSize == 0)
            return 0.0;

        stream.Seek(section.PointerToRawData, SeekOrigin.Begin);

        // Count byte frequencies in chunks to keep memory constant
        var byteCounts = new Dictionary<byte, int>(256);
        long bytesRemaining = section.RawSize;
        byte[] buffer = new byte[CHUNK_SIZE];
        long totalBytesRead = 0;

        while (bytesRemaining > 0) {
            int chunkSize = (int)Math.Min(CHUNK_SIZE, bytesRemaining);
            int bytesRead = stream.Read(buffer, 0, chunkSize);
            if (bytesRead == 0) break;

            for (int i = 0; i < bytesRead; i++) {
                byte b = buffer[i];
                if (byteCounts.TryGetValue(b, out int count))
                    byteCounts[b] = count + 1;
                else
                    byteCounts[b] = 1;
            }

            bytesRemaining -= bytesRead;
            totalBytesRead += bytesRead;
        }

        if (totalBytesRead == 0)
            return 0.0;

        // Shannon entropy: H = -Σ(p(i) × log₂(p(i)))
        double entropy = 0.0;
        foreach (var kvp in byteCounts) {
            double probability = (double)kvp.Value / totalBytesRead;
            entropy -= probability * Math.Log(probability, 2.0);
        }

        return entropy;
    }
}
