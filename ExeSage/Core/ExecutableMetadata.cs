using System;
using System.Collections.Generic;

namespace ExeSage.Core;

internal class ExecutableMetadata {
    // File identification
    public string FilePath { get; set; }
    public string FileName { get; set; }
    public long FileSize { get; set; }

    // PE header fields
    public string MachineType { get; set; }
    public string Subsystem { get; set; }
    public DateTime? CompileTime { get; set; }
    public uint AddressOfEntryPoint { get; set; }
    public uint HeaderChecksum { get; set; }

    // Digital signature
    public bool IsSigned { get; set; }
    public bool IsSignatureValid { get; set; }
    public bool IsSelfSigned { get; set; }
    public string SignerName { get; set; }
    public string CertificateIssuer { get; set; }
    public string SignatureType { get; set; }  // "Embedded", "Catalog", or null
    public string CatalogFile { get; set; }

    // Section table
    public int SectionCount { get; set; }
    public List<SectionMetadata> Sections { get; set; } = new();

    // Imports
    public List<string> ImportedDlls { get; set; } = new();
    public List<string> ImportedFunctions { get; set; } = new();
    public int ImportCount { get; set; }
    public List<SuspiciousImport> SuspiciousImports { get; set; } = new();

    // Strings
    public List<string> ExtractedStrings { get; set; } = new();
    public HashSet<string> ExtractedStringsSet { get; set; } = new();
    public List<SuspiciousString> SuspiciousStrings { get; set; } = new();

    // PE anomalies
    public List<PeAnomaly> PeAnomalies { get; set; } = new();
    public bool HasTlsCallbacks { get; set; }
    public int TlsCallbackCount { get; set; }

    // .NET detection
    public bool IsDotNet { get; set; }

    // Structural metadata
    public bool HasVersionInfo { get; set; }
    public bool HasRichHeader { get; set; }
    public int EmbeddedPeCount { get; set; }
    public string FileDescription { get; set; }
    public string ProductName { get; set; }
    public string OriginalFileName { get; set; }

    // Risk scoring
    public double RiskScore { get; set; }
    public string RiskLevel { get; set; } = "Unknown";
    public string RiskExplanation { get; set; }

    public ExecutableMetadata(string filePath) {
        FilePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        FileName = Path.GetFileName(filePath);
    }
}

internal class SectionMetadata {
    public string Name { get; set; }
    public uint VirtualSize { get; set; }
    public uint VirtualAddress { get; set; }
    public uint RawSize { get; set; }
    public uint PointerToRawData { get; set; }
    public double Entropy { get; set; }
    public bool IsExecutable { get; set; }
    public bool IsWritable { get; set; }
}

internal class SuspiciousImport {
    public string FunctionName { get; set; }
    public string Category { get; set; }
    public string Description { get; set; }
}

internal class SuspiciousString {
    public string Value { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

internal class PeAnomaly {
    public string Type { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
}
