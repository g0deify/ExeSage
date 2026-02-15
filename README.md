# ExeSage

A static PE executable analyzer that scores Windows binaries for malicious indicators without running them. Built in C# / .NET 8.

I built this because most malware analysis tools are either full sandboxes that take forever, or simple hash checkers that miss everything custom. I wanted something in between — a fast static analyzer that can look at a PE file, pull apart its structure, and tell you what's suspicious about it before you ever run it.

## What it does

- Parses PE headers, sections, imports, and strings at the byte level
- Detects suspicious API usage (injection, anti-debug, network, persistence)
- Calculates a 0–100 risk score based on weighted findings
- Verifies digital signatures (embedded Authenticode + Windows catalog)
- Handles .NET binaries (detects capabilities through namespace analysis since .NET hides API calls behind the CLR)
- Detects packers, embedded PEs, Rich header tampering, TLS callbacks
- Generates PDF forensic reports with section-by-section explanations and MITRE ATT&CK mapping

## Usage

```
dotnet run -- "C:\path\to\file.exe"
```

It'll show you the full analysis in the console, then ask if you want a PDF report.

Requires .NET 8 SDK and Windows (signature verification uses WinTrust APIs).

## Building

```
cd ExeSage/ExeSage
dotnet build -c Release
```

## Dependencies

- [QuestPDF](https://www.questpdf.com/) (PDF generation)

## What's next

- YARA rule integration
- Behavioral heuristics based on import combinations
- Better .NET IL disassembly for deeper managed code analysis
