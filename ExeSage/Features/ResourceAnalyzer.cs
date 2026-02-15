using System;
using System.IO;
using System.Linq;
using ExeSage.Core;

namespace ExeSage.Features;

/// <summary>
/// Analyzes PE resource section for embedded executables and suspicious content.
/// Dropper malware commonly hides payloads in the resource section.
/// </summary>
internal class ResourceAnalyzer
{
    private const byte MZ_SIG_0 = 0x4D; // 'M'
    private const byte MZ_SIG_1 = 0x5A; // 'Z'

    public void Analyze(ExecutableMetadata metadata)
    {
        if (metadata?.Sections == null) return;

        var rsrc = metadata.Sections.FirstOrDefault(s =>
            s.Name.Equals(".rsrc", StringComparison.OrdinalIgnoreCase));

        if (rsrc == null || rsrc.RawSize == 0) return;

        using var stream = File.OpenRead(metadata.FilePath);
        stream.Seek(rsrc.PointerToRawData, SeekOrigin.Begin);

        // Read resource section (cap at 1MB to avoid huge allocations)
        int readSize = (int)Math.Min(rsrc.RawSize, 1048576);
        byte[] data = new byte[readSize];
        int bytesRead = stream.Read(data, 0, readSize);

        int embeddedPeCount = CountEmbeddedPEs(data, bytesRead);

        if (embeddedPeCount > 0)
        {
            metadata.PeAnomalies.Add(new PeAnomaly
            {
                Type = "EmbeddedPE",
                Description = $"Found {embeddedPeCount} embedded PE executable(s) in resource section — dropper behavior",
                Severity = "High"
            });
            metadata.EmbeddedPeCount = embeddedPeCount;
        }
    }

    private int CountEmbeddedPEs(byte[] data, int length)
    {
        int count = 0;

        for (int i = 0; i < length - 64; i++)
        {
            if (data[i] != MZ_SIG_0 || data[i + 1] != MZ_SIG_1) continue;

            // Read e_lfanew (offset to PE header) at MZ+0x3C
            if (i + 0x3C + 4 >= length) continue;

            uint peOffset = BitConverter.ToUInt32(data, i + 0x3C);

            // Sanity check — PE offset should be reasonable (< 1024 bytes from MZ)
            if (peOffset < 4 || peOffset > 1024) continue;

            // Check for PE\0\0 at that offset
            long pePos = i + peOffset;
            if (pePos + 4 >= length) continue;

            if (data[pePos] == 0x50 && data[pePos + 1] == 0x45 &&
                data[pePos + 2] == 0x00 && data[pePos + 3] == 0x00)
            {
                count++;
                // Skip past this PE to avoid counting overlaps
                i += (int)Math.Min(peOffset + 256, length - i - 1);
            }
        }

        return count;
    }
}