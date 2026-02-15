using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ExeSage.Core;

namespace ExeSage.PE;

internal class PeParser {
    public void Parse(ExecutableMetadata metadata) {
        using var stream = File.OpenRead(metadata.FilePath);
        using var reader = new BinaryReader(stream);

        metadata.FileSize = stream.Length;
        metadata.FileName = Path.GetFileName(metadata.FilePath);

        // Validate DOS signature ("MZ")
        stream.Seek(0, SeekOrigin.Begin);
        ushort dosSignature = reader.ReadUInt16();
        if (dosSignature != 0x5A4D)
            throw new InvalidDataException("Invalid DOS signature");

        // e_lfanew → offset to PE header
        stream.Seek(0x3C, SeekOrigin.Begin);
        uint peHeaderOffset = reader.ReadUInt32();

        // Validate PE signature ("PE\0\0")
        stream.Seek(peHeaderOffset, SeekOrigin.Begin);
        uint peSignature = reader.ReadUInt32();
        if (peSignature != 0x00004550)
            throw new InvalidDataException("Invalid PE signature");

        // COFF Header (20 bytes)
        ushort machine = reader.ReadUInt16();
        metadata.MachineType = machine switch {
            0x014C => "I386",
            0x8664 => "AMD64",
            0xAA64 => "ARM64",
            _ => $"Unknown (0x{machine:X4})"
        };

        ushort numberOfSections = reader.ReadUInt16();
        metadata.SectionCount = numberOfSections;

        uint timeDateStamp = reader.ReadUInt32();
        try {
            metadata.CompileTime = DateTimeOffset.FromUnixTimeSeconds(timeDateStamp).UtcDateTime;
        }
        catch {
            metadata.CompileTime = null;
        }

        reader.ReadUInt32(); // PointerToSymbolTable
        reader.ReadUInt32(); // NumberOfSymbols
        ushort sizeOfOptionalHeader = reader.ReadUInt16();
        reader.ReadUInt16(); // Characteristics

        if (sizeOfOptionalHeader == 0)
            throw new InvalidDataException("No Optional Header");

        // Optional Header
        ushort magic = reader.ReadUInt16();
        bool isPe32Plus = (magic == 0x020B);

        if (magic != 0x010B && magic != 0x020B)
            throw new InvalidDataException("Invalid Optional Header magic");

        reader.ReadByte();   // MajorLinkerVersion
        reader.ReadByte();   // MinorLinkerVersion
        reader.ReadUInt32(); // SizeOfCode
        reader.ReadUInt32(); // SizeOfInitializedData
        reader.ReadUInt32(); // SizeOfUninitializedData

        metadata.AddressOfEntryPoint = reader.ReadUInt32();

        reader.ReadUInt32(); // BaseOfCode

        if (!isPe32Plus)
            reader.ReadUInt32(); // BaseOfData (PE32 only)

        if (isPe32Plus)
            reader.ReadUInt64(); // ImageBase (8 bytes for PE32+)
        else
            reader.ReadUInt32(); // ImageBase (4 bytes for PE32)

        reader.ReadUInt32(); // SectionAlignment
        reader.ReadUInt32(); // FileAlignment
        reader.ReadUInt16(); // MajorOperatingSystemVersion
        reader.ReadUInt16(); // MinorOperatingSystemVersion
        reader.ReadUInt16(); // MajorImageVersion
        reader.ReadUInt16(); // MinorImageVersion
        reader.ReadUInt16(); // MajorSubsystemVersion
        reader.ReadUInt16(); // MinorSubsystemVersion
        reader.ReadUInt32(); // Win32VersionValue
        reader.ReadUInt32(); // SizeOfImage
        reader.ReadUInt32(); // SizeOfHeaders

        metadata.HeaderChecksum = reader.ReadUInt32();

        ushort subsystem = reader.ReadUInt16();
        metadata.Subsystem = subsystem switch {
            1 => "NATIVE",
            2 => "WINDOWS_GUI",
            3 => "WINDOWS_CUI",
            _ => $"Unknown ({subsystem})"
        };

        // Skip to section headers
        long sectionHeaderStart = peHeaderOffset + 4 + 20 + sizeOfOptionalHeader;
        stream.Seek(sectionHeaderStart, SeekOrigin.Begin);

        // Section headers (40 bytes each)
        for (int i = 0; i < numberOfSections; i++) {
            byte[] nameBytes = reader.ReadBytes(8);
            string sectionName = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');

            uint virtualSize = reader.ReadUInt32();
            uint virtualAddress = reader.ReadUInt32();
            uint sizeOfRawData = reader.ReadUInt32();
            uint pointerToRawData = reader.ReadUInt32();

            reader.ReadUInt32(); // PointerToRelocations
            reader.ReadUInt32(); // PointerToLinenumbers
            reader.ReadUInt16(); // NumberOfRelocations
            reader.ReadUInt16(); // NumberOfLinenumbers

            uint characteristics = reader.ReadUInt32();

            metadata.Sections.Add(new SectionMetadata {
                Name = sectionName,
                VirtualSize = virtualSize,
                VirtualAddress = virtualAddress,
                RawSize = sizeOfRawData,
                PointerToRawData = pointerToRawData,
                IsExecutable = (characteristics & 0x20000000) != 0,
                IsWritable = (characteristics & 0x80000000) != 0,
                Entropy = 0.0
            });
        }
    }
}
