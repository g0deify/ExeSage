using System;
using System.Collections.Generic;
using System.Linq;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using ExeSage.Core;

namespace ExeSage.Report;

internal class PdfReportBuilder
{
    public void Generate(ExecutableMetadata metadata, Dictionary<string, string> analysis, string outputPath)
    {
        QuestPDF.Settings.License = LicenseType.Community;

        Document.Create(container => {
            container.Page(page => {
                page.Size(PageSizes.A4);
                page.Margin(40);
                page.DefaultTextStyle(x => x.FontSize(10).FontFamily("Arial"));

                page.Header().Element(c => ComposeHeader(c, metadata));
                page.Content().Element(c => ComposeContent(c, metadata, analysis));
                page.Footer().AlignCenter().Text(t => {
                    t.Span("ExeSage Threat Assessment Report — Page ");
                    t.CurrentPageNumber();
                    t.Span(" of ");
                    t.TotalPages();
                });
            });
        }).GeneratePdf(outputPath);
    }

    private void ComposeHeader(IContainer container, ExecutableMetadata m)
    {
        container.Column(col => {
            col.Item().Background("#1a1a2e").Padding(15).Row(row => {
                row.RelativeItem().Column(c => {
                    c.Item().Text("EXESAGE THREAT ASSESSMENT")
                        .FontSize(18).Bold().FontColor("#e94560");
                    c.Item().Text($"{m.FileName}")
                        .FontSize(12).FontColor("#ffffff");
                });
                row.ConstantItem(120).AlignRight().AlignMiddle().Column(c => {
                    var scoreColor = m.RiskLevel switch
                    {
                        "VeryLow" => "#00c853",
                        "Low" => "#64dd17",
                        "Medium" => "#ffd600",
                        "High" => "#ff6d00",
                        "Critical" => "#d50000",
                        _ => "#9e9e9e"
                    };
                    c.Item().Text($"{m.RiskScore:F0}/100")
                        .FontSize(22).Bold().FontColor(scoreColor);
                    c.Item().Text(m.RiskLevel.ToUpper())
                        .FontSize(10).FontColor(scoreColor);
                });
            });
            col.Item().PaddingVertical(5).LineHorizontal(2).LineColor("#e94560");
        });
    }

    private void ComposeContent(IContainer container, ExecutableMetadata m, Dictionary<string, string> analysis)
    {
        container.Column(col => {
            col.Spacing(8);

            // ===== FILE OVERVIEW =====
            col.Item().Text("FILE OVERVIEW").FontSize(14).Bold().FontColor("#1a1a2e");
            col.Item().Table(table => {
                table.ColumnsDefinition(c => {
                    c.ConstantColumn(160);
                    c.RelativeColumn();
                });
                AddRow(table, "File Name", m.FileName);
                AddRow(table, "Full Path", m.FilePath);
                AddRow(table, "File Size", $"{m.FileSize:N0} bytes");
                AddRow(table, "Machine Type", m.MachineType);
                AddRow(table, "Subsystem", m.Subsystem);
                AddRow(table, "Compile Time", $"{m.CompileTime:yyyy-MM-dd HH:mm:ss} UTC");
                AddRow(table, "Entry Point RVA", $"0x{m.AddressOfEntryPoint:X8}");
                AddRow(table, "Header Checksum", $"0x{m.HeaderChecksum:X8}");
                AddRow(table, ".NET Assembly", m.IsDotNet ? "Yes" : "No");
                AddRow(table, "Has Version Info", m.HasVersionInfo ? "Yes" : "No");
                AddRow(table, "Has Rich Header", m.HasRichHeader ? "Yes" : "No");
                AddRow(table, "TLS Callbacks", m.HasTlsCallbacks ? $"Yes ({m.TlsCallbackCount})" : "No");
                AddRow(table, "Embedded PEs", m.EmbeddedPeCount > 0 ? $"{m.EmbeddedPeCount} found" : "None");
            });
            AddAnalysis(col, analysis, "PeHeader");

            // ===== DIGITAL SIGNATURE =====
            col.Item().PaddingTop(10).Text("DIGITAL SIGNATURE").FontSize(14).Bold().FontColor("#1a1a2e");
            col.Item().Table(table => {
                table.ColumnsDefinition(c => {
                    c.ConstantColumn(160);
                    c.RelativeColumn();
                });
                AddRow(table, "Signed", m.IsSigned ? "Yes" : "No");
                AddRow(table, "Signature Valid", m.IsSigned ? (m.IsSignatureValid ? "Yes" : "INVALID") : "N/A");
                AddRow(table, "Signature Type", m.SignatureType ?? "None");
                AddRow(table, "Self-Signed", m.IsSelfSigned ? "Yes" : "No");
                if (!string.IsNullOrEmpty(m.SignerName))
                    AddRow(table, "Signer", m.SignerName);
                if (!string.IsNullOrEmpty(m.CertificateIssuer))
                    AddRow(table, "Issuer", m.CertificateIssuer);
                if (!string.IsNullOrEmpty(m.CatalogFile))
                    AddRow(table, "Catalog File", m.CatalogFile);
            });
            AddAnalysis(col, analysis, "Signature");

            // ===== SECTIONS =====
            col.Item().PaddingTop(10).Text("SECTION TABLE (COMPLETE)").FontSize(14).Bold().FontColor("#1a1a2e");
            col.Item().Table(table => {
                table.ColumnsDefinition(c => {
                    c.RelativeColumn(2); c.RelativeColumn(2); c.RelativeColumn(2);
                    c.RelativeColumn(2); c.RelativeColumn(2); c.RelativeColumn(1.5f);
                    c.RelativeColumn(1); c.RelativeColumn(1);
                });
                table.Header(h => {
                    foreach (var header in new[] { "Name", "Virt Addr", "Virt Size", "Raw Offset", "Raw Size", "Entropy", "Exec", "Write" })
                        h.Cell().Background("#1a1a2e").Padding(3).Text(header).FontSize(8).Bold().FontColor("#ffffff");
                });
                foreach (var s in m.Sections)
                {
                    var bg = s.Entropy > 7.0 ? "#ffcdd2" : (s.Entropy > 6.5 ? "#fff9c4" : "#ffffff");
                    table.Cell().Background(bg).Padding(2).Text(s.Name).FontSize(8);
                    table.Cell().Background(bg).Padding(2).Text($"0x{s.VirtualAddress:X8}").FontSize(8);
                    table.Cell().Background(bg).Padding(2).Text($"{s.VirtualSize:N0}").FontSize(8);
                    table.Cell().Background(bg).Padding(2).Text($"0x{s.PointerToRawData:X8}").FontSize(8);
                    table.Cell().Background(bg).Padding(2).Text($"{s.RawSize:N0}").FontSize(8);
                    table.Cell().Background(bg).Padding(2).Text($"{s.Entropy:F2}").FontSize(8);
                    table.Cell().Background(bg).Padding(2).Text(s.IsExecutable ? "Y" : "N").FontSize(8);
                    table.Cell().Background(bg).Padding(2).Text(s.IsWritable ? "Y" : "N").FontSize(8);
                }
            });
            col.Item().Text("Red = entropy > 7.0 (packed/encrypted) | Yellow = entropy > 6.5 (elevated)").FontSize(7).FontColor("#999999");
            AddAnalysis(col, analysis, "Sections");

            // ===== IMPORTS =====
            col.Item().PaddingTop(10).Text($"COMPLETE IMPORT TABLE ({m.ImportCount} functions from {m.ImportedDlls.Count} DLLs)")
                .FontSize(14).Bold().FontColor("#1a1a2e");

            var importsByDll = m.ImportedFunctions
                .Select(f => { int sep = f.IndexOf('!'); return sep > 0 ? new { Dll = f[..sep], Func = f[(sep + 1)..], Full = f } : new { Dll = "Unknown", Func = f, Full = f }; })
                .GroupBy(x => x.Dll).OrderBy(g => g.Key);

            var suspFuncs = m.SuspiciousImports.Select(i => i.FunctionName).ToHashSet();

            foreach (var dllGroup in importsByDll)
            {
                col.Item().PaddingTop(4).Text(dllGroup.Key).FontSize(9).Bold().FontColor("#333333");
                foreach (var func in dllGroup)
                {
                    bool isSusp = suspFuncs.Contains(func.Full);
                    var detail = isSusp ? m.SuspiciousImports.FirstOrDefault(i => i.FunctionName == func.Full) : null;
                    if (isSusp)
                    {
                        col.Item().PaddingLeft(15).Row(row => {
                            row.AutoItem().Text($"⚠ {func.Func}").FontSize(8).Bold().FontColor("#d50000");
                            row.AutoItem().PaddingLeft(5).Text($"[{detail?.Category}] {detail?.Description}").FontSize(7).FontColor("#e94560");
                        });
                    }
                    else
                    {
                        col.Item().PaddingLeft(15).Text($"  {func.Func}").FontSize(8).FontColor("#555555");
                    }
                }
            }
            AddAnalysis(col, analysis, "Imports");

            // ===== STRINGS =====
            col.Item().PaddingTop(10).Text($"STRING ANALYSIS ({m.ExtractedStrings.Count} total, {m.SuspiciousStrings.Count} flagged)")
                .FontSize(14).Bold().FontColor("#1a1a2e");

            // Suspicious strings first — these are the important ones
            if (m.SuspiciousStrings.Count > 0)
            {
                col.Item().PaddingTop(4).Text("Flagged Strings:").FontSize(10).Bold().FontColor("#e94560");
                foreach (var group in m.SuspiciousStrings.GroupBy(s => s.Category))
                {
                    col.Item().PaddingTop(3).Text($"[{group.Key}] ({group.Count()})").FontSize(9).Bold().FontColor("#d50000");
                    foreach (var s in group)
                    {
                        col.Item().PaddingLeft(15).Text($"⚠ {s.Value}").FontSize(8).Bold().FontColor("#d50000");
                        col.Item().PaddingLeft(25).Text(s.Description).FontSize(7).FontColor("#666666");
                    }
                }
            }

            // Compact categorized string summary instead of dumping every string
            col.Item().PaddingTop(5).Text("String Summary:").FontSize(10).Bold().FontColor("#333333");

            var urls = m.ExtractedStrings.Where(s => s.Contains("://")).Take(15).ToList();
            var paths = m.ExtractedStrings.Where(s => s.Contains("\\") && s.Length > 10 && !s.Contains("://")).Take(15).ToList();
            var dlls = m.ExtractedStrings.Where(s => s.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)).Distinct().Take(20).ToList();
            var exes = m.ExtractedStrings.Where(s => s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)).Distinct().Take(15).ToList();
            var commands = m.ExtractedStrings.Where(s =>
                s.Contains("cmd", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("whoami", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("net ", StringComparison.OrdinalIgnoreCase))
                .Distinct().Take(10).ToList();
            var registry = m.ExtractedStrings.Where(s =>
                s.Contains("HKEY_", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("SOFTWARE\\", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("CurrentVersion", StringComparison.OrdinalIgnoreCase))
                .Distinct().Take(10).ToList();

            PrintStringGroup(col, "URLs", urls);
            PrintStringGroup(col, "File Paths", paths);
            PrintStringGroup(col, "Referenced DLLs", dlls);
            PrintStringGroup(col, "Referenced Executables", exes);
            PrintStringGroup(col, "Commands / Shell", commands);
            PrintStringGroup(col, "Registry References", registry);

            int shown = urls.Count + paths.Count + dlls.Count + exes.Count + commands.Count + registry.Count + m.SuspiciousStrings.Count;
            int omitted = m.ExtractedStrings.Count - shown;
            if (omitted > 0)
                col.Item().PaddingTop(5).Text($"  + {omitted:N0} additional strings omitted (generic runtime strings, constants, etc.)")
                    .FontSize(7).Italic().FontColor("#999999");

            AddAnalysis(col, analysis, "Strings");

            // ===== ANOMALIES =====
            col.Item().PaddingTop(10).Text("PE STRUCTURAL ANOMALIES").FontSize(14).Bold().FontColor("#1a1a2e");
            if (m.PeAnomalies.Count > 0)
            {
                foreach (var a in m.PeAnomalies)
                {
                    var sevColor = a.Severity switch { "High" => "#d50000", "Medium" => "#ff6d00", _ => "#666666" };
                    col.Item().PaddingTop(2).Row(row => {
                        row.ConstantItem(55).Text($"[{a.Severity}]").FontSize(9).Bold().FontColor(sevColor);
                        row.ConstantItem(80).Text($"[{a.Type}]").FontSize(9).Bold().FontColor("#333333");
                        row.RelativeItem().Text(a.Description).FontSize(9);
                    });
                }
            }
            else
            {
                col.Item().Text("No structural anomalies detected.").FontSize(9).FontColor("#00c853");
            }
            AddAnalysis(col, analysis, "Anomalies");

            // ===== FINAL VERDICT =====
            col.Item().PaddingTop(15).LineHorizontal(2).LineColor("#e94560");
            col.Item().PaddingTop(10).Text("FINAL VERDICT").FontSize(16).Bold().FontColor("#1a1a2e");
            AddAnalysis(col, analysis, "Verdict");

            col.Item().PaddingTop(10).Background("#1a1a2e").Padding(15).Column(c => {
                var scoreColor = m.RiskLevel switch
                {
                    "VeryLow" => "#00c853",
                    "Low" => "#64dd17",
                    "Medium" => "#ffd600",
                    "High" => "#ff6d00",
                    "Critical" => "#d50000",
                    _ => "#9e9e9e"
                };
                c.Item().Text($"Risk Score: {m.RiskScore:F1}/100 — {m.RiskLevel}")
                    .FontSize(16).Bold().FontColor(scoreColor);
            });

            col.Item().PaddingTop(10).Text($"Report generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC by ExeSage v0.1.0")
                .FontSize(8).FontColor("#999999");
        });
    }

    private void PrintStringGroup(ColumnDescriptor col, string label, List<string> items)
    {
        if (items.Count == 0) return;
        col.Item().PaddingTop(4).Text($"  {label} ({items.Count}):").FontSize(8).Bold().FontColor("#444444");
        foreach (var s in items)
            col.Item().PaddingLeft(20).Text(s).FontSize(7).FontColor("#555555");
    }

    private void AddAnalysis(ColumnDescriptor col, Dictionary<string, string> analysis, string key)
    {
        if (analysis == null || !analysis.ContainsKey(key) || string.IsNullOrEmpty(analysis[key])) return;

        col.Item().PaddingTop(5).PaddingBottom(5).PaddingLeft(10).PaddingRight(10)
            .Background("#f5f5f5").Border(1).BorderColor("#e0e0e0").Padding(10).Column(c => {
                c.Item().Text("Forensic Analysis").FontSize(9).Bold().FontColor("#e94560");
                c.Item().PaddingTop(3).Text(analysis[key]).FontSize(9).LineHeight(1.4f).FontColor("#333333");
            });
    }

    private void AddRow(TableDescriptor table, string label, string value)
    {
        table.Cell().BorderBottom(1).BorderColor("#eeeeee").Padding(4)
            .Text(label).FontSize(9).Bold();
        table.Cell().BorderBottom(1).BorderColor("#eeeeee").Padding(4)
            .Text(value ?? "N/A").FontSize(9);
    }
}