using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using ExeSage.Core;

namespace ExeSage.Features;

/// <summary>
/// Extracts ASCII/Unicode strings from PE sections and flags suspicious patterns.
/// Covers: encoded data, network indicators, shell commands, .NET metadata,
/// persistence paths, sandbox evasion, and credential access.
/// </summary>
internal class StringAnalyzer {
    private const int MIN_STRING_LENGTH = 4;
    private const int MAX_STRING_LENGTH = 1024;
    private const int MIN_BASE64_LENGTH = 20;
    private const double HIGH_ENTROPY_THRESHOLD = 5.5;

    private static readonly Regex Base64Pattern = new(@"^[A-Za-z0-9+/]{20,}={0,2}$", RegexOptions.Compiled);
    private static readonly Regex IpPattern = new(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", RegexOptions.Compiled);
    private static readonly Regex UrlPattern = new(@"(?:https?|ftp|tcp|mqtt|ws|wss)://[^\s<>""]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // host:port pattern — catches raw C2 addresses like 192.168.1.50:1883
    private static readonly Regex HostPortPattern = new(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b", RegexOptions.Compiled);

    private static readonly string[] SuspiciousPaths = {
        @"\AppData\Roaming", @"\AppData\Local\Temp", @"\Windows\Temp",
        @"%TEMP%", @"%APPDATA%",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    };

    private static readonly string[] SandboxKeywords = {
        "vmware", "virtualbox", "vbox", "qemu", "sandboxie",
        "wireshark", "procmon", "ollydbg", "windbg", "ida",
        "x64dbg", "immunity", "sample", "malware", "virus", "infected"
    };

    // Shell commands that should be matched as substrings (they include path/extension context)
    private static readonly string[] ShellSubstringIndicators = {
        "cmd.exe", "powershell.exe", "cmd /c", "cmd.exe /c",
        "/bin/sh", "/bin/bash",
        "certutil -decode", "certutil -urlcache",
        "bitsadmin /transfer",
        "powershell -enc", "powershell -e ", "powershell -nop",
    };

    // Shell/recon commands that must be whole-word matched to avoid false positives
    // (e.g., "systeminfo" inside "NtQuerySystemInformation" is not suspicious)
    private static readonly string[] ShellWholeWordIndicators = {
        "whoami", "ipconfig", "tasklist", "taskkill",
        "netstat", "systeminfo", "wmic", "schtasks",
        "mshta", "regsvr32", "rundll32", "wscript", "cscript",
    };

    // .NET namespaces that indicate suspicious capabilities when found in metadata
    private static readonly (string Pattern, string Description)[] DotNetSuspiciousNamespaces = {
        ("System.Net.Sockets", "Raw socket access"),
        ("System.Diagnostics.Process", "Process execution capability"),
        ("System.Security.Cryptography", "Cryptographic operations"),
        ("System.Runtime.InteropServices", "Native interop / P/Invoke"),
        ("System.Reflection.Assembly", "Dynamic assembly loading"),
        ("System.IO.Pipes", "Named pipe communication"),
        ("Microsoft.Win32.Registry", "Registry access"),
        ("System.Management", "WMI access"),
        ("System.ServiceProcess", "Windows service manipulation"),
        ("System.Net.Http", "HTTP client capability"),
        ("System.Net.NetworkInformation", "Network reconnaissance"),
    };

    // Keywords suggesting credential theft or data exfiltration
    // Deliberately excludes common terms like "clipboard" that appear in normal app frameworks
    private static readonly string[] ExfilKeywords = {
        "password", "passwd", "credential", "keylog",
        "screenshot", "webcam", "microphone",
        "exfil", "steal", "harvest", "dump"
    };

    private static readonly string[] TrustedUrlDomains = {
        "microsoft.com", "windows.com", "windowsupdate.com",
        "google.com", "apple.com", "mozilla.org",
        "github.com", "digicert.com", "verisign.com",
        "symantec.com", "globalsign.com"
    };

    public void Analyze(ExecutableMetadata metadata) {
        if (metadata == null)
            throw new ArgumentNullException(nameof(metadata));

        if (metadata.Sections == null || metadata.Sections.Count == 0)
            return;

        using var stream = File.OpenRead(metadata.FilePath);

        foreach (var section in metadata.Sections) {
            if (section.Name.StartsWith(".rsrc")) continue;
            if (section.RawSize == 0 || section.PointerToRawData == 0) continue;

            try {
                ExtractStringsFromSection(stream, section, metadata);
            }
            catch { }
        }

        CategorizeStrings(metadata);
    }

    private void ExtractStringsFromSection(Stream stream, SectionMetadata section, ExecutableMetadata metadata) {
        stream.Seek(section.PointerToRawData, SeekOrigin.Begin);
        byte[] data = new byte[section.RawSize];
        int bytesRead = stream.Read(data, 0, (int)section.RawSize);

        ExtractAsciiStrings(data, bytesRead, metadata);
        ExtractUnicodeStrings(data, bytesRead, metadata);
    }

    private void ExtractAsciiStrings(byte[] data, int length, ExecutableMetadata metadata) {
        var current = new List<byte>();

        for (int i = 0; i < length; i++) {
            byte b = data[i];
            if (b >= 0x20 && b <= 0x7E) {
                current.Add(b);
                if (current.Count >= MAX_STRING_LENGTH) {
                    SaveString(current, metadata);
                    current.Clear();
                }
            }
            else {
                if (current.Count >= MIN_STRING_LENGTH)
                    SaveString(current, metadata);
                current.Clear();
            }
        }

        if (current.Count >= MIN_STRING_LENGTH)
            SaveString(current, metadata);
    }

    private void ExtractUnicodeStrings(byte[] data, int length, ExecutableMetadata metadata) {
        var current = new List<byte>();

        for (int i = 0; i < length - 1; i += 2) {
            byte lo = data[i];
            byte hi = data[i + 1];

            if (hi == 0x00 && lo >= 0x20 && lo <= 0x7E) {
                current.Add(lo);
                if (current.Count >= MAX_STRING_LENGTH) {
                    SaveString(current, metadata);
                    current.Clear();
                }
            }
            else {
                if (current.Count >= MIN_STRING_LENGTH)
                    SaveString(current, metadata);
                current.Clear();
            }
        }

        if (current.Count >= MIN_STRING_LENGTH)
            SaveString(current, metadata);
    }

    private void SaveString(List<byte> bytes, ExecutableMetadata metadata) {
        if (bytes.Count == 0) return;

        string str = Encoding.ASCII.GetString(bytes.ToArray()).Trim();

        if (str.Length >= MIN_STRING_LENGTH && metadata.ExtractedStringsSet.Add(str))
            metadata.ExtractedStrings.Add(str);
    }

    private bool IsLikelyBase64(string str) {
        if (!Base64Pattern.IsMatch(str)) return false;

        double upperRatio = (double)str.Count(char.IsUpper) / str.Length;
        if (upperRatio > 0.2 && upperRatio < 0.8) return false;

        return str.Contains('+') || str.Contains('/') || str.EndsWith('=');
    }

    private bool IsTrustedUrl(string url) {
        string lower = url.ToLowerInvariant();
        return TrustedUrlDomains.Any(domain => lower.Contains(domain));
    }

    private void CategorizeStrings(ExecutableMetadata metadata) {
        // Track what we've already flagged to avoid duplicate hits on the same string
        var flagged = new HashSet<string>();

        foreach (var str in metadata.ExtractedStrings) {
            // Base64
            if (str.Length >= MIN_BASE64_LENGTH && IsLikelyBase64(str)) {
                AddSuspicious(metadata, flagged, str, "Base64", "Base64 encoded data (possible payload)", 50);
            }

            // IP addresses
            foreach (Match match in IpPattern.Matches(str)) {
                if (IsValidIp(match.Value) && !IsFalsePositiveIp(match.Value)) {
                    AddSuspicious(metadata, flagged, match.Value, "IpAddress",
                        "Hardcoded IP address (possible C2 server)");
                }
            }

            // host:port patterns (catches raw C2 like 192.168.1.50:1883)
            foreach (Match match in HostPortPattern.Matches(str)) {
                string ip = match.Value.Split(':')[0];
                if (IsValidIp(ip) && !IsFalsePositiveIp(ip)) {
                    AddSuspicious(metadata, flagged, match.Value, "IpAddress",
                        "Hardcoded IP:port (likely C2 or service endpoint)");
                }
            }

            // URLs (including non-HTTP protocols like mqtt://, tcp://, ws://)
            foreach (Match match in UrlPattern.Matches(str)) {
                if (!IsTrustedUrl(match.Value)) {
                    string proto = match.Value.Split("://")[0].ToLower();
                    string desc = proto switch {
                        "mqtt" or "tcp" or "ws" or "wss" => $"Non-HTTP URL ({proto}://) — possible C2 channel",
                        _ => "URL found (possible download/C2 endpoint)"
                    };
                    AddSuspicious(metadata, flagged, Truncate(match.Value, 60), "Url", desc);
                }
            }

            // Shell / command execution — substring match for paths with extensions
            string lower = str.ToLowerInvariant();
            foreach (var indicator in ShellSubstringIndicators) {
                if (lower.Contains(indicator.ToLowerInvariant())) {
                    AddSuspicious(metadata, flagged, Truncate(str, 60), "ShellExecution",
                        $"Shell/command execution: '{indicator}'");
                    break;
                }
            }

            // Shell / recon commands — whole-word match to avoid false positives
            // (e.g., "systeminfo" inside "NtQuerySystemInformation" is NOT a hit)
            var words = lower.Split(new[] { ' ', '.', '-', '_', '/', '\\', ':', '|', '(', ')' },
                                    StringSplitOptions.RemoveEmptyEntries);

            foreach (var indicator in ShellWholeWordIndicators) {
                if (words.Contains(indicator.ToLowerInvariant())) {
                    AddSuspicious(metadata, flagged, Truncate(str, 60), "ShellExecution",
                        $"Recon/execution command: '{indicator}'");
                    break;
                }
            }

            // .NET suspicious namespaces (only check for .NET binaries)
            if (metadata.IsDotNet) {
                foreach (var (pattern, desc) in DotNetSuspiciousNamespaces) {
                    if (str.Contains(pattern, StringComparison.Ordinal)) {
                        AddSuspicious(metadata, flagged, pattern, "DotNetCapability",
                            $".NET capability: {desc}");
                        break;
                    }
                }
            }

            // Suspicious paths
            foreach (var path in SuspiciousPaths) {
                if (str.Contains(path, StringComparison.OrdinalIgnoreCase)) {
                    AddSuspicious(metadata, flagged, Truncate(str, 60), "SuspiciousPath",
                        "Suspicious path (common malware location)");
                    break;
                }
            }

            // Sandbox/VM detection keywords (whole-word match, reuses words from above)
            foreach (var keyword in SandboxKeywords) {
                if (words.Contains(keyword)) {
                    AddSuspicious(metadata, flagged, Truncate(str, 60), "SandboxDetection",
                        $"Sandbox/VM detection string: '{keyword}'");
                    break;
                }
            }

            // Credential / exfiltration keywords
            foreach (var keyword in ExfilKeywords) {
                if (words.Contains(keyword)) {
                    AddSuspicious(metadata, flagged, Truncate(str, 60), "CredentialAccess",
                        $"Credential/exfil keyword: '{keyword}'");
                    break;
                }
            }

            // High-entropy strings
            if (str.Length >= 10) {
                double entropy = CalculateStringEntropy(str);
                if (entropy > HIGH_ENTROPY_THRESHOLD) {
                    AddSuspicious(metadata, flagged, Truncate(str, 60), "Obfuscated",
                        $"High entropy string (entropy={entropy:F2}, possible encryption)");
                }
            }
        }
    }

    private void AddSuspicious(ExecutableMetadata metadata, HashSet<string> flagged,
        string value, string category, string description, int truncLen = 0) {

        string display = truncLen > 0 ? Truncate(value, truncLen) : value;
        string key = $"{category}:{display}";

        if (flagged.Add(key)) {
            metadata.SuspiciousStrings.Add(new SuspiciousString {
                Value = display,
                Category = category,
                Description = description
            });
        }
    }

    private bool IsValidIp(string ip) {
        var parts = ip.Split('.');
        if (parts.Length != 4) return false;
        return parts.All(p => int.TryParse(p, out int n) && n >= 0 && n <= 255);
    }

    private bool IsFalsePositiveIp(string ip) {
        return ip.StartsWith("0.") || ip.StartsWith("1.0.") || ip.StartsWith("2.0.") || ip == "127.0.0.1";
    }

    private double CalculateStringEntropy(string str) {
        var freq = new Dictionary<char, int>();
        foreach (char c in str)
            freq[c] = freq.GetValueOrDefault(c) + 1;

        double entropy = 0;
        foreach (var count in freq.Values) {
            double p = (double)count / str.Length;
            if (p > 0) entropy -= p * Math.Log(p, 2);
        }
        return entropy;
    }

    private string Truncate(string str, int maxLength) =>
        str.Length <= maxLength ? str : str[..maxLength] + "...";
}
