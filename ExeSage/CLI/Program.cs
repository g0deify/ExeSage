using ExeSage.Core;
using ExeSage.Report;
using System;
using System.IO;
using System.Linq;

namespace ExeSage.CLI;

class Program {
    static int Main(string[] args) {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("ExeSage - PE Executable Risk Assessment Tool");
        Console.WriteLine("Version 0.1.0");
        Console.ResetColor();
        Console.WriteLine();

        if (args.Length != 1) {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Usage: exesage <path-to-executable>");
            Console.ResetColor();
            return 1;
        }

        string filePath;
        try {
            filePath = Path.GetFullPath(args[0]);
        }
        catch (Exception ex) {
            PrintError($"Invalid file path - {ex.Message}");
            return 1;
        }

        if (!File.Exists(filePath)) {
            PrintError($"File not found - {filePath}");
            return 2;
        }

        Console.WriteLine($"Analyzing: {Path.GetFileName(filePath)}");
        Console.WriteLine();

        try {
            var orchestrator = new AnalysisOrchestrator();
            var metadata = orchestrator.Analyze(filePath);
            DisplayResults(metadata);

            // Ask if user wants a report
            Console.Write("\n[Report] Generate PDF report? (Y/N): ");
            string reportChoice = Console.ReadLine()?.Trim().ToUpper();

            if (reportChoice == "Y")
            {
                // Ask where to save using Windows Save File Dialog via PowerShell
                string defaultName = Path.GetFileNameWithoutExtension(filePath) + ".report.pdf";
                string savePath = ShowSaveDialog(defaultName);

                if (!string.IsNullOrEmpty(savePath))
                {
                    Console.Write("[Analysis] Generating forensic assessment...");
                    var engine = new AnalysisEngine();
                    var analysis = engine.Analyze(metadata);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine(" done");
                    Console.ResetColor();

                    try
                    {
                        var pdfBuilder = new PdfReportBuilder();
                        pdfBuilder.Generate(metadata, analysis, savePath);
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine($"[Report] Saved: {savePath}");
                        Console.ResetColor();

                        // Ask to open
                        Console.Write("[Report] Open report? (Y/N): ");
                        string openChoice = Console.ReadLine()?.Trim().ToUpper();
                        if (openChoice == "Y")
                        {
                            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                            {
                                FileName = savePath,
                                UseShellExecute = true
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"[Report] PDF generation failed: {ex.Message}");
                        Console.ResetColor();
                    }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("[Report] Cancelled.");
                    Console.ResetColor();
                }
            }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Analysis complete.");
            Console.ResetColor();
            return 0;
        }
        catch (InvalidDataException ex) {
            PrintError($"Not a valid PE executable - {ex.Message}");
            return 3;
        }
        catch (UnauthorizedAccessException) {
            PrintError("Access denied - run as administrator or check file permissions");
            return 4;
        }
        catch (Exception ex) {
            PrintError($"Unexpected error - {ex.GetType().Name}: {ex.Message}");
            return 99;
        }
    }

    static void PrintError(string message) {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Error: {message}");
        Console.ResetColor();
    }

    static void PrintHeader(string title) {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"=== {title} ===");
        Console.ResetColor();
    }

    static void DisplayResults(ExecutableMetadata metadata) {
        // File info
        PrintHeader("FILE INFORMATION");
        Console.WriteLine($"File Name:     {Path.GetFileName(metadata.FilePath)}");
        Console.WriteLine($"File Size:     {metadata.FileSize:N0} bytes");
        Console.WriteLine($"File Path:     {metadata.FilePath}");

        // PE header
        Console.WriteLine();
        PrintHeader("PE HEADER INFORMATION");
        Console.WriteLine($"Machine Type:  {metadata.MachineType}");
        Console.WriteLine($"Subsystem:     {metadata.Subsystem}");
        Console.WriteLine($"Compile Time:  {metadata.CompileTime:yyyy-MM-dd HH:mm:ss} UTC");
        if (metadata.IsDotNet) {
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine($"Runtime:       .NET (CLR) — imports resolved at runtime, limited static visibility");
            Console.ResetColor();
        }

        // Sections
        Console.WriteLine();
        PrintHeader("SECTIONS");
        Console.WriteLine($"Section Count: {metadata.Sections.Count}");
        Console.WriteLine();
        Console.WriteLine($"{"Name",-12} {"VirtSize",10} {"RawSize",10} {"Entropy",8} {"Exec",-4} {"Write",-5}");
        Console.WriteLine(new string('-', 60));

        foreach (var s in metadata.Sections) {
            Console.WriteLine($"{s.Name,-12} {s.VirtualSize,10:N0} {s.RawSize,10:N0} {s.Entropy,8:F2} " +
                            $"{(s.IsExecutable ? "Y" : "N"),4} {(s.IsWritable ? "Y" : "N"),5}");
        }

        // Signature
        Console.WriteLine();
        PrintHeader("DIGITAL SIGNATURE");
        Console.Write("Signed:        ");
        if (metadata.IsSigned) {
            Console.ForegroundColor = metadata.IsSignatureValid ? ConsoleColor.Green : ConsoleColor.Red;
            string typeLabel = !string.IsNullOrEmpty(metadata.SignatureType) ? $", {metadata.SignatureType}" : "";
            Console.WriteLine(metadata.IsSignatureValid
                ? $"Yes (valid{typeLabel})"
                : $"Yes (INVALID{typeLabel})");
        }
        else {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("No (unsigned file)");
        }
        Console.ResetColor();

        if (!string.IsNullOrEmpty(metadata.SignerName))
            Console.WriteLine($"Signer:        {metadata.SignerName}");
        if (!string.IsNullOrEmpty(metadata.CatalogFile))
            Console.WriteLine($"Catalog:       {metadata.CatalogFile}");

        // Imports
        Console.WriteLine();
        PrintHeader("IMPORTS");
        Console.WriteLine($"Import Count:  {metadata.ImportCount}");
        Console.WriteLine($"DLL Count:     {metadata.ImportedDlls.Count}");

        if (metadata.ImportedDlls.Count > 0) {
            Console.WriteLine();
            Console.WriteLine("Imported DLLs:");
            foreach (var dll in metadata.ImportedDlls.Take(10))
                Console.WriteLine($"  - {dll}");

            if (metadata.ImportedDlls.Count > 10) {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  ... and {metadata.ImportedDlls.Count - 10} more");
                Console.ResetColor();
            }
        }

        if (metadata.SuspiciousImports.Count > 0) {
            // Filter out weak signals from the "suspicious" count — they're informational
            var strongImports = metadata.SuspiciousImports.Where(i => i.Category != "AntiDebugWeak").ToList();
            var weakImports = metadata.SuspiciousImports.Where(i => i.Category == "AntiDebugWeak").ToList();

            if (strongImports.Count > 0) {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Suspicious Imports ({strongImports.Count}):");
                Console.ResetColor();

                foreach (var group in strongImports.GroupBy(i => i.Category).OrderByDescending(g => g.Count())) {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"  [{group.Key}]");
                    Console.ResetColor();

                    foreach (var import in group.Take(5)) {
                        Console.WriteLine($"    - {import.FunctionName}");
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine($"      {import.Description}");
                        Console.ResetColor();
                    }
                    if (group.Count() > 5) {
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine($"    ... and {group.Count() - 5} more");
                        Console.ResetColor();
                    }
                }
            }

            if (weakImports.Count > 0) {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"Low-Signal Imports ({weakImports.Count}) — common in normal applications:");
                foreach (var import in weakImports.Take(5)) {
                    Console.WriteLine($"    - {import.FunctionName}");
                }
                Console.ResetColor();
            }

            if (strongImports.Count == 0 && weakImports.Count > 0) {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("No high-confidence suspicious imports detected.");
                Console.ResetColor();
            }
        }
        else {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("No suspicious imports detected.");
            Console.ResetColor();
        }

        // Strings
        Console.WriteLine();
        PrintHeader("STRING ANALYSIS");
        Console.WriteLine($"Extracted Strings: {metadata.ExtractedStrings.Count:N0}");
        Console.WriteLine($"Suspicious Strings: {metadata.SuspiciousStrings.Count}");

        if (metadata.SuspiciousStrings.Count > 0) {
            Console.WriteLine();
            Console.WriteLine("Suspicious Patterns:");

            foreach (var group in metadata.SuspiciousStrings.GroupBy(s => s.Category).OrderByDescending(g => g.Count())) {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"\n  [{group.Key}] ({group.Count()})");
                Console.ResetColor();

                foreach (var item in group.Take(5)) {
                    Console.WriteLine($"    {item.Value}");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"    └─ {item.Description}");
                    Console.ResetColor();
                }
                if (group.Count() > 5) {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"    ... and {group.Count() - 5} more");
                    Console.ResetColor();
                }
            }
        }
        else {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("No suspicious strings detected.");
            Console.ResetColor();
        }

        // PE anomalies
        Console.WriteLine();
        PrintHeader("PE STRUCTURAL ANOMALIES");

        if (metadata.PeAnomalies.Count > 0) {
            foreach (var group in metadata.PeAnomalies.GroupBy(a => a.Severity)
                .OrderByDescending(g => g.Key switch { "High" => 3, "Medium" => 2, "Low" => 1, _ => 0 })) {

                ConsoleColor color = group.Key switch {
                    "High" => ConsoleColor.Red,
                    "Medium" => ConsoleColor.Yellow,
                    "Low" => ConsoleColor.DarkYellow,
                    _ => ConsoleColor.Gray
                };

                Console.ForegroundColor = color;
                Console.WriteLine($"\n  [{group.Key} Severity] ({group.Count()})");
                Console.ResetColor();

                foreach (var anomaly in group) {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write($"    [{anomaly.Type}] ");
                    Console.ResetColor();
                    Console.WriteLine(anomaly.Description);
                }
            }
        }
        else {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("No structural anomalies detected.");
            Console.ResetColor();
        }

        // Risk assessment
        Console.WriteLine();
        PrintHeader("RISK ASSESSMENT");

        ConsoleColor scoreColor = metadata.RiskLevel switch {
            "VeryLow" => ConsoleColor.Green,
            "Low" => ConsoleColor.DarkGreen,
            "Medium" => ConsoleColor.Yellow,
            "High" => ConsoleColor.Red,
            "Critical" => ConsoleColor.DarkRed,
            _ => ConsoleColor.Gray
        };

        Console.ForegroundColor = scoreColor;
        Console.Write($"Risk Score:  {metadata.RiskScore:F1}/100");
        Console.ResetColor();
        Console.WriteLine($"  ({metadata.RiskLevel} Risk)");

        string guidance = metadata.RiskLevel switch {
            "VeryLow" => "Safe to run - no significant concerns detected",
            "Low" => "Probably safe - minor concerns present",
            "Medium" => "Investigate before running - multiple suspicious indicators",
            "High" => "Likely malicious - avoid running",
            "Critical" => "Almost certainly malware - do NOT run",
            _ => "Unable to assess risk"
        };

        Console.WriteLine($"Guidance:    {guidance}");
    }

    private static string ShowSaveDialog(string defaultFileName)
    {
        try
        {
            // Use PowerShell to invoke Windows SaveFileDialog — works from console apps
            string script = $@"
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.SaveFileDialog
$dialog.Filter = 'PDF Files (*.pdf)|*.pdf'
$dialog.FileName = '{defaultFileName}'
$dialog.Title = 'Save ExeSage Report'
$dialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
if ($dialog.ShowDialog() -eq 'OK') {{ Write-Output $dialog.FileName }}
";
            var process = new System.Diagnostics.Process();
            process.StartInfo.FileName = "powershell";
            process.StartInfo.Arguments = $"-NoProfile -Command \"{script.Replace("\"", "\\\"").Replace("\n", " ")}\"";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();

            string result = process.StandardOutput.ReadToEnd().Trim();
            process.WaitForExit();

            return string.IsNullOrEmpty(result) ? null : result;
        }
        catch
        {
            // Fallback if PowerShell dialog fails
            Console.Write("[Report] Save to (press Enter for Desktop): ");
            string path = Console.ReadLine()?.Trim().Trim('"');

            if (string.IsNullOrEmpty(path))
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), defaultFileName);

            if (Directory.Exists(path))
                return Path.Combine(path, defaultFileName);

            if (!path.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase))
                path += ".pdf";

            return path;
        }
    }
}
