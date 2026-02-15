using System;
using System.IO;
using ExeSage.Core;

namespace ExeSage.Features;

/// <summary>
/// Analyzes the undocumented Rich header (between DOS stub and PE header).
/// Contains build tool metadata. Tampered Rich headers suggest recompilation
/// or tool signature masking.
/// </summary>
internal class RichHeaderAnalyzer
{
    // "Rich" marker (end of Rich header)
    private static readonly byte[] RICH_MARKER = { 0x52, 0x69, 0x63, 0x68 }; // "Rich"
    // "DanS" marker (start of Rich header, XOR'd with key)
    private const uint DANS_SIGNATURE = 0x536E6144; // "DanS"

    public void Analyze(ExecutableMetadata metadata)
    {
        if (metadata == null) return;

        using var stream = File.OpenRead(metadata.FilePath);
        using var reader = new BinaryReader(stream);

        // Get PE header offset
        stream.Seek(0x3C, SeekOrigin.Begin);
        uint peOffset = reader.ReadUInt32();

        // Rich header lives between ~0x80 (after DOS stub) and peOffset
        if (peOffset < 0x80 || peOffset > 1024) return;

        // Read the region between DOS stub and PE header
        stream.Seek(0, SeekOrigin.Begin);
        byte[] header = new byte[peOffset];
        if (stream.Read(header, 0, (int)peOffset) != peOffset) return;

        // Find "Rich" marker
        int richOffset = -1;
        for (int i = (int)peOffset - 4; i >= 0x80; i--)
        {
            if (header[i] == RICH_MARKER[0] && header[i + 1] == RICH_MARKER[1] &&
                header[i + 2] == RICH_MARKER[2] && header[i + 3] == RICH_MARKER[3])
            {
                richOffset = i;
                break;
            }
        }

        if (richOffset == -1)
        {
            // No Rich header — could be stripped or non-MSVC toolchain
            metadata.HasRichHeader = false;
            return;
        }

        metadata.HasRichHeader = true;

        // XOR key is the 4 bytes after "Rich"
        uint xorKey = BitConverter.ToUInt32(header, richOffset + 4);

        // Find "DanS" marker (start of Rich header) by XOR-decrypting backwards
        int dansOffset = -1;
        for (int i = 0x80; i < richOffset; i += 4)
        {
            uint decrypted = BitConverter.ToUInt32(header, i) ^ xorKey;
            if (decrypted == DANS_SIGNATURE)
            {
                dansOffset = i;
                break;
            }
        }

        if (dansOffset == -1)
        {
            metadata.PeAnomalies.Add(new PeAnomaly
            {
                Type = "RichHeader",
                Description = "Rich header found but DanS marker missing — header may be corrupted or tampered",
                Severity = "High"
            });
            return;
        }

        // Validate Rich header checksum
        // The XOR key should equal a checksum of the DOS header + Rich header entries
        uint calculatedChecksum = CalculateRichChecksum(header, dansOffset, xorKey);

        if (calculatedChecksum != xorKey)
        {
            metadata.PeAnomalies.Add(new PeAnomaly
            {
                Type = "RichHeader",
                Description = $"Rich header checksum mismatch (expected 0x{xorKey:X8}, calculated 0x{calculatedChecksum:X8}) — tampered or recompiled",
                Severity = "High"
            });
        }
    }

    private uint CalculateRichChecksum(byte[] header, int dansOffset, uint xorKey)
    {
        uint checksum = (uint)dansOffset;

        // Part 1: Sum of DOS header bytes, each rotated left by its position
        for (int i = 0; i < dansOffset; i++)
        {
            if (i >= 0x3C && i < 0x40) continue; // Skip e_lfanew
            checksum += RotateLeft((uint)header[i], i);
        }

        // Part 2: Rich header entries (after DanS + 3 padding DWORDs)
        // Each entry is 8 bytes: compId (4 bytes) + useCount (4 bytes)
        // Checksum += RotateLeft(compId, useCount) for each entry
        int entryStart = dansOffset + 16; // DanS(4) + 3 padding DWORDs(12)
        for (int i = entryStart; i < header.Length - 8; i += 8)
        {
            // Check if we've hit the "Rich" marker (unencrypted)
            // Since data is XOR'd, we need to decrypt first
            uint word1 = BitConverter.ToUInt32(header, i) ^ xorKey;
            uint word2 = BitConverter.ToUInt32(header, i + 4) ^ xorKey;

            // If word1 is "Rich" (0x68636952), we've gone too far
            if (BitConverter.ToUInt32(header, i) == 0x68636952) break;

            checksum += RotateLeft(word1, (int)(word2 & 0x1F));
        }

        return checksum;
    }

    private uint RotateLeft(uint value, int count)
    {
        count &= 31;
        return (value << count) | (value >> (32 - count));
    }
}