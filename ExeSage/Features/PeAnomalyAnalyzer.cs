using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ExeSage.Core;

namespace ExeSage.Features;

/// <summary>
/// Detects PE structural anomalies: entry point issues, section manipulation,
/// timestamp tampering, TLS callbacks, debug stripping, checksum mismatches.
/// </summary>
internal class PeAnomalyAnalyzer {
    private static readonly DateTime MinReasonableTimestamp = new(2000, 1, 1);
    private const int MaxNormalSections = 8;
    private const int MinNormalSections = 2;

    public void Analyze(ExecutableMetadata metadata) {
        if (metadata == null)
            throw new ArgumentNullException(nameof(metadata));

        if (metadata.Sections == null || metadata.Sections.Count == 0)
            return;

        CheckEntryPointLocation(metadata);
        CheckSectionAnomalies(metadata);
        CheckTimestamp(metadata);
        CheckSectionCount(metadata);
        CheckTlsCallbacks(metadata);
        CheckDebugDirectory(metadata);
        CheckHeaderChecksum(metadata);
        CheckResourceEntropy(metadata);
        CheckVersionInfo(metadata);
    }

    private void CheckVersionInfo(ExecutableMetadata metadata)
    {
        if (!metadata.HasVersionInfo)
        {
            metadata.PeAnomalies.Add(new PeAnomaly
            {
                Type = "VersionInfo",
                Description = "No version information found — legitimate software typically includes this",
                Severity = "Medium"
            });
        }
    }

    private void CheckResourceEntropy(ExecutableMetadata metadata)
    {
        var rsrc = metadata.Sections.FirstOrDefault(s =>
            s.Name.Equals(".rsrc", StringComparison.OrdinalIgnoreCase));

        if (rsrc == null || rsrc.RawSize == 0) return;

        // .rsrc above 7.0 entropy = encrypted/compressed payload hiding in resources
        if (rsrc.Entropy > 7.0)
        {
            metadata.PeAnomalies.Add(new PeAnomaly
            {
                Type = "Resource",
                Description = $"Resource section has high entropy ({rsrc.Entropy:F2}) — possible encrypted payload",
                Severity = "High"
            });
        }
        // 6.5-7.0 is suspicious but could be compressed images
        else if (rsrc.Entropy > 6.5)
        {
            metadata.PeAnomalies.Add(new PeAnomaly
            {
                Type = "Resource",
                Description = $"Resource section has elevated entropy ({rsrc.Entropy:F2}) — may contain compressed/encrypted data",
                Severity = "Medium"
            });
        }
    }

    private void CheckEntryPointLocation(ExecutableMetadata metadata) {
        if (metadata.AddressOfEntryPoint == 0) return;

        uint ep = metadata.AddressOfEntryPoint;
        int sectionIndex = -1;
        SectionMetadata entrySection = null;

        for (int i = 0; i < metadata.Sections.Count; i++) {
            var s = metadata.Sections[i];
            if (ep >= s.VirtualAddress && ep < s.VirtualAddress + s.VirtualSize) {
                sectionIndex = i;
                entrySection = s;
                break;
            }
        }

        if (entrySection == null) {
            metadata.PeAnomalies.Add(new PeAnomaly {
                Type = "EntryPoint",
                Description = "Entry point not found in any section",
                Severity = "High"
            });
            return;
        }

        if (!entrySection.Name.Equals(".text", StringComparison.OrdinalIgnoreCase)) {
            metadata.PeAnomalies.Add(new PeAnomaly {
                Type = "EntryPoint",
                Description = $"Entry point in unusual section '{entrySection.Name}' (expected .text)",
                Severity = "High"
            });
        }

        // Last-section entry point is a classic packer indicator
        if (sectionIndex == metadata.Sections.Count - 1) {
            metadata.PeAnomalies.Add(new PeAnomaly {
                Type = "EntryPoint",
                Description = "Entry point in last section (common packer behavior)",
                Severity = "Medium"
            });
        }
    }

    private void CheckSectionAnomalies(ExecutableMetadata metadata) {
        foreach (var section in metadata.Sections) {
            // Zero raw size + non-zero virtual = unpacking buffer
            if (section.RawSize == 0 && section.VirtualSize > 0) {
                metadata.PeAnomalies.Add(new PeAnomaly {
                    Type = "Section",
                    Description = $"Section '{section.Name}' has zero raw size but virtual size {section.VirtualSize:N0} (unpacking indicator)",
                    Severity = section.IsExecutable ? "High" : "Medium"
                });
            }

            if (IsSuspiciousSectionName(section.Name)) {
                metadata.PeAnomalies.Add(new PeAnomaly {
                    Type = "Section",
                    Description = $"Suspicious section name '{section.Name}' (common in packers)",
                    Severity = "Medium"
                });
            }
        }

        // Overlapping sections
        for (int i = 0; i < metadata.Sections.Count; i++) {
            var s1 = metadata.Sections[i];
            uint s1End = s1.VirtualAddress + s1.VirtualSize;

            for (int j = i + 1; j < metadata.Sections.Count; j++) {
                if (metadata.Sections[j].VirtualAddress < s1End) {
                    metadata.PeAnomalies.Add(new PeAnomaly {
                        Type = "Section",
                        Description = $"Sections '{s1.Name}' and '{metadata.Sections[j].Name}' overlap (PE manipulation)",
                        Severity = "High"
                    });
                }
            }
        }
    }

    private bool IsSuspiciousSectionName(string name) {
        string[] suspicious = {
            "UPX0", "UPX1", "UPX2",
            ".packed", ".pack",
            ".nsp0", ".nsp1", ".nsp2",
            ".aspack", ".adata",
            ".petite",
            ".text0", ".text1", ".text2",
            ".themida", ".winlice",
            ".enigma", ".enigma1", ".enigma2",
            ".vmp0", ".vmp1", ".vmp2",
            ".rsrc_a", "MEW",
            ".boom", ".ccg", ".charmve"
        };

        return suspicious.Any(s => name.Equals(s, StringComparison.OrdinalIgnoreCase));
    }

    private void CheckTimestamp(ExecutableMetadata metadata) {
        if (!metadata.CompileTime.HasValue) return;

        DateTime ts = metadata.CompileTime.Value;
        DateTime now = DateTime.UtcNow;

        if (ts > now.AddDays(1)) {
            // Future timestamps are common in reproducible/deterministic builds (MSVC /Brepro, Go, Delphi).
            // Suspicious but not high-severity on its own.
            metadata.PeAnomalies.Add(new PeAnomaly {
                Type = "Timestamp",
                Description = $"Compilation timestamp is in the future ({ts:yyyy-MM-dd}) — may indicate reproducible build or manipulation",
                Severity = "Medium"
            });
        }

        if (ts < MinReasonableTimestamp) {
            metadata.PeAnomalies.Add(new PeAnomaly {
                Type = "Timestamp",
                Description = $"Compilation timestamp is suspiciously old ({ts:yyyy-MM-dd})",
                Severity = "Medium"
            });
        }

        // Near Unix epoch = likely timestomping
        if (ts.Year < 1980) {
            metadata.PeAnomalies.Add(new PeAnomaly {
                Type = "Timestamp",
                Description = $"Compilation timestamp appears manipulated ({ts:yyyy-MM-dd}, near Unix epoch)",
                Severity = "High"
            });
        }
    }

    private void CheckSectionCount(ExecutableMetadata metadata) {
        int count = metadata.SectionCount;

        if (count < MinNormalSections) {
            metadata.PeAnomalies.Add(new PeAnomaly {
                Type = "Structure",
                Description = $"Very few sections ({count}, expected {MinNormalSections}+)",
                Severity = "Medium"
            });
        }

        if (count > MaxNormalSections) {
            metadata.PeAnomalies.Add(new PeAnomaly {
                Type = "Structure",
                Description = $"Unusually many sections ({count}, normal is {MinNormalSections}-{MaxNormalSections})",
                Severity = "Low"
            });
        }
    }

    private void CheckTlsCallbacks(ExecutableMetadata metadata) {
        try {
            using var stream = File.OpenRead(metadata.FilePath);
            using var reader = new BinaryReader(stream);

            stream.Seek(0x3C, SeekOrigin.Begin);
            uint peOffset = reader.ReadUInt32();

            stream.Seek(peOffset, SeekOrigin.Begin);
            if (reader.ReadUInt32() != 0x00004550) return;

            stream.Seek(peOffset + 4 + 20, SeekOrigin.Begin);
            ushort magic = reader.ReadUInt16();
            bool isPe32Plus = (magic == 0x020B);

            // TLS = DataDirectory[9]
            int dataDirStart = isPe32Plus ? 112 : 96;
            stream.Seek(peOffset + 4 + 20 + dataDirStart + (9 * 8), SeekOrigin.Begin);

            uint tlsRva = reader.ReadUInt32();
            uint tlsSize = reader.ReadUInt32();

            if (tlsRva != 0 && tlsSize > 0) {
                metadata.HasTlsCallbacks = true;
                metadata.PeAnomalies.Add(new PeAnomaly {
                    Type = "TLS",
                    Description = "TLS callbacks present (pre-entry execution, possible anti-debug)",
                    Severity = "Medium"
                });
            }
        }
        catch { }
    }

    private void CheckDebugDirectory(ExecutableMetadata metadata) {
        try {
            using var stream = File.OpenRead(metadata.FilePath);
            using var reader = new BinaryReader(stream);

            stream.Seek(0x3C, SeekOrigin.Begin);
            uint peOffset = reader.ReadUInt32();

            stream.Seek(peOffset, SeekOrigin.Begin);
            if (reader.ReadUInt32() != 0x00004550) return;

            stream.Seek(peOffset + 4 + 20, SeekOrigin.Begin);
            ushort magic = reader.ReadUInt16();
            bool isPe32Plus = (magic == 0x020B);

            // Debug = DataDirectory[6]
            int dataDirStart = isPe32Plus ? 112 : 96;
            stream.Seek(peOffset + 4 + 20 + dataDirStart + (6 * 8), SeekOrigin.Begin);

            uint debugRva = reader.ReadUInt32();

            if (debugRva == 0) {
                metadata.PeAnomalies.Add(new PeAnomaly {
                    Type = "Debug",
                    Description = "Debug directory stripped (anti-analysis or release build)",
                    Severity = "Low"
                });
            }
        }
        catch { }
    }

    private void CheckHeaderChecksum(ExecutableMetadata metadata) {
        if (metadata.HeaderChecksum == 0) return; // Not set — normal for user-mode apps

        try {
            using var stream = File.OpenRead(metadata.FilePath);
            uint calculated = CalculatePeChecksum(stream);

            if (calculated != metadata.HeaderChecksum) {
                metadata.PeAnomalies.Add(new PeAnomaly {
                    Type = "Checksum",
                    Description = $"Header checksum mismatch (expected 0x{metadata.HeaderChecksum:X8}, calculated 0x{calculated:X8})",
                    Severity = "Medium"
                });
            }
        }
        catch { }
    }

    /// <summary>
    /// PE checksum: 16-bit word sum with carry folding, skipping the checksum field itself.
    /// </summary>
    private uint CalculatePeChecksum(Stream stream) {
        // Locate the checksum field so we can skip it during summation
        stream.Seek(0x3C, SeekOrigin.Begin);
        byte[] buf4 = new byte[4];
        stream.Read(buf4, 0, 4);
        uint peHeaderOffset = BitConverter.ToUInt32(buf4, 0);
        long checksumFieldOffset = peHeaderOffset + 4 + 20 + 64;

        stream.Seek(0, SeekOrigin.Begin);
        uint checksum = 0;
        byte[] buffer = new byte[2];
        long position = 0;

        while (stream.Read(buffer, 0, 2) == 2) {
            // Skip the 4-byte checksum field
            if (position != checksumFieldOffset && position != checksumFieldOffset + 2) {
                checksum += BitConverter.ToUInt16(buffer, 0);
                checksum = (checksum & 0xFFFF) + (checksum >> 16);
            }
            position += 2;
        }

        checksum = (checksum & 0xFFFF) + (checksum >> 16); // Final fold
        checksum += (uint)stream.Length;

        return checksum;
    }
}
