using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ExeSage.Core;

namespace ExeSage.Report;

/// <summary>
/// Template-based analysis engine that maps structured PE findings
/// to expert forensic explanations. Generates detailed section-by-section
/// writeups covering PE headers, signatures, imports, strings, and anomalies.
/// </summary>
internal class AnalysisEngine
{

    public Dictionary<string, string> Analyze(ExecutableMetadata m)
    {
        return new Dictionary<string, string>
        {
            ["PeHeader"] = AnalyzePeHeader(m),
            ["Signature"] = AnalyzeSignature(m),
            ["Sections"] = AnalyzeSections(m),
            ["Imports"] = AnalyzeImports(m),
            ["Strings"] = AnalyzeStrings(m),
            ["Anomalies"] = AnalyzeAnomalies(m),
            ["Verdict"] = GenerateVerdict(m),
        };
    }

    private string AnalyzePeHeader(ExecutableMetadata m)
    {
        var sb = new StringBuilder();

        // Machine type
        sb.Append($"This is a {m.MachineType} ");
        sb.Append(m.MachineType switch
        {
            "AMD64" => "(64-bit x86-64) ",
            "I386" => "(32-bit x86) ",
            _ => ""
        });

        // Subsystem
        sb.Append(m.Subsystem switch
        {
            "WINDOWS_GUI" => "graphical Windows application. ",
            "WINDOWS_CUI" => "console-based Windows application. ",
            _ => $"binary with subsystem '{m.Subsystem}'. "
        });

        // .NET
        if (m.IsDotNet)
        {
            sb.Append("The binary is a .NET (CLR) assembly, meaning its code runs through the Common Language Runtime. " +
                "Import analysis is limited because .NET resolves API calls at runtime rather than through the PE import table. " +
                "String analysis and .NET namespace detection are the primary indicators for managed binaries. ");
        }

        // Compile timestamp
        if (m.CompileTime.HasValue && m.CompileTime.Value.Year > DateTime.UtcNow.Year)
        {
            sb.Append($"The compilation timestamp ({m.CompileTime.Value:yyyy-MM-dd}) is in the future, which typically indicates " +
                "either a deterministic/reproducible build system (common with Microsoft binaries) or deliberate timestamp manipulation " +
                "to hinder forensic timeline analysis. ");
        }
        else if (m.CompileTime.HasValue && m.CompileTime.Value.Year < 2000)
        {
            sb.Append($"The compilation timestamp ({m.CompileTime.Value:yyyy-MM-dd}) is anomalously old, suggesting timestamp manipulation " +
                        "or a zeroed-out PE header. This is a common anti-forensics technique. ");
        }
        else if (m.CompileTime.HasValue)
        {
            sb.Append($"The compilation timestamp ({m.CompileTime.Value:yyyy-MM-dd HH:mm:ss} UTC) falls within a plausible range. ");
        }

        // Entry point
        sb.Append($"Entry point is at RVA 0x{m.AddressOfEntryPoint:X8}. ");

        // Version info
        if (!m.HasVersionInfo)
            sb.Append("No version information resource was found — legitimate commercial and system software almost always includes " +
                "version info (FileDescription, CompanyName, ProductVersion). Its absence is a moderate indicator of non-standard or malicious origin. ");
        else
            sb.Append("Version information is present, which is expected for legitimate software. ");

        // Rich header
        if (m.HasRichHeader)
            sb.Append("A Rich header was detected, indicating the binary was compiled with Microsoft Visual Studio toolchain. ");
        else
            sb.Append("No Rich header was found — the binary may have been compiled with a non-MSVC toolchain (MinGW, Clang, Delphi, Go, Rust) " +
                "or the Rich header was deliberately stripped as an anti-analysis measure. ");

        return sb.ToString();
    }

    private string AnalyzeSignature(ExecutableMetadata m)
    {
        var sb = new StringBuilder();

        if (!m.IsSigned)
        {
            sb.Append("This file is NOT digitally signed. The absence of a digital signature means the publisher's identity " +
                "cannot be verified and the file integrity cannot be validated cryptographically. While unsigned software exists " +
                "legitimately (open-source tools, personal projects), the lack of a signature is a weak risk indicator that " +
                "compounds with other findings. Most commercial and system software is signed. ");
            return sb.ToString();
        }

        sb.Append($"The file is digitally signed using {m.SignatureType ?? "unknown"} signing. ");

        if (m.SignatureType == "Catalog")
        {
            sb.Append("Catalog signing means the file's cryptographic hash is stored in a Windows catalog (.cat) file " +
                "in the system's CatRoot store, rather than having a signature embedded in the PE itself. " +
                "This is the standard signing method for Windows system components — Microsoft signs the catalog file, " +
                "which vouches for all files whose hashes it contains. ");
            if (!string.IsNullOrEmpty(m.CatalogFile))
                sb.Append($"The specific catalog file is '{m.CatalogFile}'. ");
        }
        else if (m.SignatureType == "Embedded")
        {
            sb.Append("Embedded Authenticode signing means the digital signature is stored within the PE file itself " +
                "in a dedicated certificate directory. This is the standard signing method for third-party software. ");
        }

        if (m.IsSignatureValid)
        {
            sb.Append("The signature is VALID — the file has not been tampered with since it was signed, " +
                "and the certificate chain is trusted. ");
        }
        else
        {
            sb.Append("WARNING: The signature is INVALID. This could indicate the file has been modified after signing " +
                "(possible tampering), the signing certificate has been revoked, or the certificate chain cannot be verified. " +
                "This is a significant trust concern. ");
        }

        if (m.IsSelfSigned)
        {
            sb.Append("CAUTION: The certificate is self-signed — it was not issued by a trusted Certificate Authority (CA). " +
                "Anyone can create a self-signed certificate, so this provides no assurance of publisher identity. " +
                "Malware frequently uses self-signed certificates to appear 'signed' to superficial checks. ");
        }

        if (!string.IsNullOrEmpty(m.SignerName))
            sb.Append($"The signer is identified as '{m.SignerName}'. ");

        return sb.ToString();
    }

    private string AnalyzeSections(ExecutableMetadata m)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"The binary contains {m.Sections.Count} sections:");
        sb.AppendLine();

        foreach (var s in m.Sections)
        {
            sb.Append($"• {s.Name}: ");

            // Explain what the section is
            string sectionPurpose = s.Name.ToLower().TrimEnd('\0') switch
            {
                ".text" => "Primary code section containing executable instructions",
                ".rdata" => "Read-only data section (constants, import/export tables, debug info)",
                ".data" => "Initialized global and static data",
                ".bss" => "Uninitialized data section",
                ".rsrc" => "Windows resources (icons, version info, embedded files, dialogs)",
                ".reloc" => "Base relocation table for ASLR support",
                ".pdata" => "Exception handling information (structured exception handlers)",
                ".idata" => "Import directory table",
                ".edata" => "Export directory table",
                ".tls" => "Thread Local Storage — can contain TLS callbacks that execute before entry point",
                ".didat" => "Delay-load import directory",
                ".crt" => "C runtime initialization data",
                _ when s.Name.Contains("UPX", StringComparison.OrdinalIgnoreCase) => "UPX packer section — this binary has been packed with UPX",
                _ when s.Name.Contains("nsp", StringComparison.OrdinalIgnoreCase) => "NSPack packer section — this binary has been packed",
                _ when s.Name.StartsWith(".") => $"Standard PE section",
                _ => $"Non-standard section name — unusual names can indicate packers, protectors, or custom build tools"
            };
            sb.Append($"{sectionPurpose}. ");

            // Entropy analysis
            if (s.Entropy > 7.5)
                sb.Append($"Entropy is {s.Entropy:F2} (VERY HIGH) — strongly indicates encrypted or compressed content. " +
                    "Packed malware typically shows entropy above 7.5 in executable sections. ");
            else if (s.Entropy > 7.0)
                sb.Append($"Entropy is {s.Entropy:F2} (HIGH) — suggests packed, compressed, or encrypted data. " +
                    "Normal compiled code rarely exceeds 7.0 entropy. ");
            else if (s.Entropy > 6.5)
                sb.Append($"Entropy is {s.Entropy:F2} (elevated but within normal range). " +
                    "Compiled code typically falls between 5.5-6.5. Compressed resources can push this higher. ");
            else if (s.Entropy > 4.0)
                sb.Append($"Entropy is {s.Entropy:F2} (normal). ");
            else if (s.Entropy > 0.5)
                sb.Append($"Entropy is {s.Entropy:F2} (low — sparse data or padding). ");
            else
                sb.Append($"Entropy is {s.Entropy:F2} (near zero — mostly null bytes or minimal data). ");

            // Permission analysis
            if (s.IsExecutable && s.IsWritable)
                sb.Append("WARNING: Section is both EXECUTABLE and WRITABLE (RWX) — this is a strong indicator " +
                    "of self-modifying code, runtime unpacking, or shellcode execution. Legitimate software rarely needs RWX sections. ");
            else if (s.IsExecutable)
                sb.Append("Section is executable (expected for code sections). ");
            else if (s.IsWritable)
                sb.Append("Section is writable (expected for data sections). ");

            // Size anomalies
            if (s.RawSize == 0 && s.VirtualSize > 0)
                sb.Append("Raw size is 0 but virtual size is non-zero — the section content is generated at runtime, " +
                    "which is a common indicator of runtime unpacking. ");

            sb.AppendLine();
        }

        return sb.ToString();
    }

    private string AnalyzeImports(ExecutableMetadata m)
    {
        var sb = new StringBuilder();

        if (m.IsDotNet && m.ImportCount <= 2)
        {
            sb.AppendLine($"This .NET binary imports only {m.ImportCount} function(s) from {m.ImportedDlls.Count} DLL(s), " +
                "which is expected for managed code. .NET executables typically only import _CorExeMain from mscoree.dll — " +
                "all actual API calls are resolved at runtime through the CLR. For .NET binaries, string analysis and " +
                "namespace detection provide better insight into capabilities than import analysis.");
            sb.AppendLine();
        }
        else
        {
            sb.AppendLine($"The binary imports {m.ImportCount} functions from {m.ImportedDlls.Count} DLLs.");
            sb.AppendLine();
        }

        // Low import count warning
        if (!m.IsDotNet && m.ImportCount > 0 && m.ImportCount < 10)
        {
            sb.AppendLine($"⚠ VERY LOW IMPORT COUNT ({m.ImportCount}): Legitimate native binaries typically import " +
                "dozens to hundreds of functions. A very low count strongly suggests the binary uses dynamic API resolution " +
                "(GetProcAddress/LoadLibrary) at runtime to hide its true capabilities, or is packed with a stub loader. " +
                "This is a common malware evasion technique.");
            sb.AppendLine();
        }

        // Analyze by category
        if (m.SuspiciousImports.Count > 0)
        {
            sb.AppendLine($"⚠ {m.SuspiciousImports.Count} SUSPICIOUS IMPORTS DETECTED:");
            sb.AppendLine();

            var categories = m.SuspiciousImports.GroupBy(i => i.Category).OrderByDescending(g => g.Count());

            foreach (var cat in categories)
            {
                string catExplanation = cat.Key switch
                {
                    "ProcessInjection" => "PROCESS INJECTION — These APIs enable injecting code into other running processes. " +
                        "This is a primary technique used by malware for defense evasion (running malicious code within a trusted process), " +
                        "privilege escalation, and persistence. Common techniques: DLL injection, process hollowing, APC injection. " +
                        "MITRE ATT&CK: T1055 (Process Injection).",

                    "MemoryManipulation" => "MEMORY MANIPULATION — These APIs modify memory permissions and allocate executable regions. " +
                        "VirtualAlloc with PAGE_EXECUTE_READWRITE and VirtualProtect to change pages to executable are hallmarks of " +
                        "shellcode loaders and in-memory payload execution. MITRE ATT&CK: T1055 (Process Injection), T1620 (Reflective Loading).",

                    "ProcessExecution" => "PROCESS EXECUTION — APIs for creating new processes. While used by legitimate software, " +
                        "in the context of other suspicious indicators, these enable malware to launch additional payloads, execute " +
                        "shell commands, or spawn child processes for defense evasion. MITRE ATT&CK: T1059 (Command and Scripting Interpreter).",

                    "AntiDebug" => "ANTI-DEBUG (STRONG) — These APIs are specifically used to detect or evade debuggers. " +
                        "NtQueryInformationProcess with ProcessDebugPort, CheckRemoteDebuggerPresent, and NtSetInformationThread " +
                        "with ThreadHideFromDebugger are classic anti-analysis techniques. Legitimate software very rarely uses these. " +
                        "MITRE ATT&CK: T1622 (Debugger Evasion).",

                    "AntiDebugWeak" => "ANTI-DEBUG (WEAK) — IsDebuggerPresent and OutputDebugString are commonly used in normal applications " +
                        "for debugging support. These alone are not suspicious but gain significance when combined with strong anti-debug indicators.",

                    "Network" => "NETWORK COMMUNICATION — These APIs enable network connectivity. In combination with other suspicious " +
                        "indicators, they suggest Command & Control (C2) communication, data exfiltration, or payload downloading. " +
                        "MITRE ATT&CK: T1071 (Application Layer Protocol), T1105 (Ingress Tool Transfer).",

                    "Cryptography" => "CRYPTOGRAPHY — Encryption/decryption APIs. Could indicate ransomware (encrypting files), " +
                        "secure C2 communication, credential theft, or legitimate data protection. Context-dependent — " +
                        "suspicious when combined with network and file operation imports.",

                    "PersistenceRegistry" => "REGISTRY PERSISTENCE — APIs for modifying the Windows registry. When targeting " +
                        "Run/RunOnce keys, these are used to establish persistence across reboots. " +
                        "MITRE ATT&CK: T1547.001 (Registry Run Keys).",

                    "PersistenceService" => "SERVICE PERSISTENCE — APIs for creating and managing Windows services. Malware uses these " +
                        "to install itself as a service for persistence with SYSTEM privileges. " +
                        "MITRE ATT&CK: T1543.003 (Windows Service).",

                    "FileOperation" => "FILE OPERATIONS — File manipulation APIs (delete, move, copy). In malware context, " +
                        "these enable self-deletion after execution, file dropping, or file system manipulation. " +
                        "MITRE ATT&CK: T1070.004 (Indicator Removal: File Deletion).",

                    _ => $"{cat.Key} — Flagged API category."
                };

                sb.AppendLine($"  [{cat.Key}] — {cat.Count()} API(s) flagged");
                sb.AppendLine($"  {catExplanation}");
                foreach (var imp in cat)
                {
                    sb.AppendLine($"    • {imp.FunctionName} — {imp.Description}");
                }
                sb.AppendLine();
            }

            // Combination analysis
            var catNames = categories.Select(c => c.Key).ToHashSet();
            if (catNames.Contains("ProcessInjection") && catNames.Contains("Network"))
                sb.AppendLine("⚠ CRITICAL COMBINATION: Process Injection + Network = Classic RAT/backdoor pattern. " +
                    "The binary can inject into remote processes AND communicate over the network.");
            if (catNames.Contains("Network") && catNames.Contains("Cryptography"))
                sb.AppendLine("⚠ NOTABLE COMBINATION: Network + Cryptography = Encrypted C2 communication or ransomware pattern.");
            if (catNames.Contains("ProcessInjection") && catNames.Contains("AntiDebug"))
                sb.AppendLine("⚠ NOTABLE COMBINATION: Process Injection + Anti-Debug = Evasive malware pattern. " +
                    "The binary actively resists analysis while performing code injection.");
        }
        else
        {
            sb.AppendLine("No suspicious imports were flagged. The import profile appears benign.");
        }

        // DLL summary
        sb.AppendLine();
        sb.AppendLine("Imported DLLs provide the following capabilities:");
        var dllCapabilities = CategorizeDlls(m.ImportedDlls);
        foreach (var (category, dlls) in dllCapabilities)
        {
            sb.AppendLine($"  {category}: {string.Join(", ", dlls)}");
        }

        return sb.ToString();
    }

    private List<(string Category, List<string> Dlls)> CategorizeDlls(List<string> dlls)
    {
        var result = new List<(string, List<string>)>();
        var categories = new Dictionary<string, List<string>>
        {
            ["GUI/Graphics"] = new(),
            ["System/Core"] = new(),
            ["Network"] = new(),
            ["Security/Crypto"] = new(),
            ["Runtime"] = new(),
            ["Other"] = new()
        };

        foreach (var dll in dlls)
        {
            string lower = dll.ToLowerInvariant();
            if (lower.Contains("gdi") || lower.Contains("user32") || lower.Contains("comctl") || lower.Contains("shell32"))
                categories["GUI/Graphics"].Add(dll);
            else if (lower.Contains("kernel32") || lower.Contains("ntdll") || lower.Contains("api-ms-win-core"))
                categories["System/Core"].Add(dll);
            else if (lower.Contains("ws2") || lower.Contains("winhttp") || lower.Contains("wininet") || lower.Contains("urlmon") || lower.Contains("netapi"))
                categories["Network"].Add(dll);
            else if (lower.Contains("crypt") || lower.Contains("bcrypt") || lower.Contains("ncrypt") || lower.Contains("advapi"))
                categories["Security/Crypto"].Add(dll);
            else if (lower.Contains("msvc") || lower.Contains("crt") || lower.Contains("mscoree") || lower.Contains("vcruntime"))
                categories["Runtime"].Add(dll);
            else
                categories["Other"].Add(dll);
        }

        foreach (var (cat, list) in categories)
        {
            if (list.Count > 0)
                result.Add((cat, list));
        }
        return result;
    }

    private string AnalyzeStrings(ExecutableMetadata m)
    {
        var sb = new StringBuilder();

        sb.AppendLine($"{m.ExtractedStrings.Count} strings were extracted from the binary. " +
            $"{m.SuspiciousStrings.Count} matched suspicious patterns.");
        sb.AppendLine();

        if (m.SuspiciousStrings.Count == 0)
        {
            sb.AppendLine("No suspicious string patterns were identified. The extracted strings appear consistent " +
                "with normal application behavior. ");

            if (m.IsDotNet)
            {
                sb.Append(".NET metadata strings (namespace references, type names) were analyzed for suspicious " +
                    "capabilities but none were flagged. ");
            }
            return sb.ToString();
        }

        var groups = m.SuspiciousStrings.GroupBy(s => s.Category).OrderByDescending(g => g.Count());

        foreach (var group in groups)
        {
            string explanation = group.Key switch
            {
                "IpAddress" => "HARDCODED IP ADDRESSES — Embedded IP addresses often indicate C2 server endpoints, " +
                    "download locations, or network targets. Legitimate software typically uses domain names or configuration files " +
                    "rather than hardcoded IPs. Each IP should be checked against threat intelligence feeds.",

                "Url" => "URLS DETECTED — Embedded URLs may indicate C2 endpoints, payload download locations, " +
                    "or data exfiltration targets. Non-HTTP protocols (mqtt://, tcp://, ws://) are particularly suspicious " +
                    "as they suggest custom C2 channels.",

                "ShellExecution" => "SHELL/COMMAND EXECUTION — References to command interpreters (cmd.exe, powershell) " +
                    "and system reconnaissance tools (whoami, ipconfig, tasklist) are hallmarks of RATs and C2 implants. " +
                    "These enable remote command execution on compromised systems. " +
                    "MITRE ATT&CK: T1059.001 (PowerShell), T1059.003 (Windows Command Shell).",

                "DotNetCapability" => ".NET CAPABILITIES — These namespace references reveal the managed code's actual capabilities " +
                    "since .NET import analysis is limited. Each namespace maps to specific functionality that the binary can invoke at runtime.",

                "Base64" => "BASE64 ENCODED DATA — Long Base64 strings embedded in a binary often contain encoded payloads, " +
                    "configuration data, encryption keys, or obfuscated commands. Malware frequently uses Base64 to evade " +
                    "simple string-based detection.",

                "SuspiciousPath" => "SUSPICIOUS FILE PATHS — References to common malware staging directories (AppData\\Roaming, " +
                    "Temp, Windows\\Temp) or persistence locations (Run/RunOnce registry keys) suggest file dropping, " +
                    "staging, or persistence behavior.",

                "SandboxDetection" => "SANDBOX/VM DETECTION — Keywords related to analysis tools and virtual environments indicate " +
                    "the binary attempts to detect if it's running in an analysis sandbox. This is a strong evasion indicator — " +
                    "legitimate software has no reason to check for VMware, VirtualBox, or debugging tools. " +
                    "MITRE ATT&CK: T1497 (Virtualization/Sandbox Evasion).",

                "Obfuscated" => "HIGH ENTROPY STRINGS — Strings with unusually high entropy (randomness) suggest encrypted data, " +
                    "encoded payloads, or obfuscated content. These may contain encrypted configuration, C2 parameters, or embedded payloads.",

                "CredentialAccess" => "CREDENTIAL ACCESS KEYWORDS — References to passwords, credentials, or data harvesting suggest " +
                    "the binary may attempt credential theft or data exfiltration. " +
                    "MITRE ATT&CK: T1003 (OS Credential Dumping), T1555 (Credentials from Password Stores).",

                _ => $"Flagged string category: {group.Key}"
            };

            sb.AppendLine($"[{group.Key}] — {group.Count()} match(es)");
            sb.AppendLine(explanation);
            sb.AppendLine();
            foreach (var s in group.Take(10))
            {
                sb.AppendLine($"  • \"{s.Value}\"");
            }
            if (group.Count() > 10)
                sb.AppendLine($"  ... and {group.Count() - 10} more");
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private string AnalyzeAnomalies(ExecutableMetadata m)
    {
        var sb = new StringBuilder();

        if (m.PeAnomalies.Count == 0)
        {
            sb.Append("No structural anomalies were detected in the PE file. The header structure, section layout, " +
                "entry point location, timestamps, and checksums all appear normal. This is consistent with a properly " +
                "compiled, unmodified binary.");
            return sb.ToString();
        }

        sb.AppendLine($"{m.PeAnomalies.Count} structural anomaly(ies) detected:");
        sb.AppendLine();

        foreach (var a in m.PeAnomalies)
        {
            sb.AppendLine($"• [{a.Severity}] {a.Type}: {a.Description}");

            string explanation = a.Type switch
            {
                "EntryPoint" => "  The entry point location is abnormal. Legitimate compilers place the entry point in the .text section. " +
                    "Entry points outside .text or in the last section are characteristic of packers, crypters, and manually modified binaries.",

                "Section" => a.Description.Contains("overlap") ?
                    "  Overlapping sections indicate PE header manipulation, which is used by some packers and exploit payloads " +
                    "to confuse static analysis tools." :
                    a.Description.Contains("raw size is 0") ?
                    "  A section with zero raw size but non-zero virtual size means its content is generated at runtime — " +
                    "a classic unpacking stub indicator." :
                    "  Section anomaly detected — may indicate PE manipulation or non-standard build tooling.",

                "Timestamp" => "  Timestamp anomalies can indicate: reproducible builds (Microsoft uses future dates), " +
                    "timestomping (anti-forensics to confuse timeline analysis), or zeroed headers (deliberate sanitization).",

                "TLS" => "  TLS (Thread Local Storage) callbacks execute BEFORE the main entry point. Malware uses TLS callbacks " +
                    "for anti-debug checks, early-stage decryption, or to execute code before debuggers can attach. " +
                    "MITRE ATT&CK: T1622 (Debugger Evasion).",

                "Checksum" => "  Header checksum mismatch means the PE was modified after compilation without updating the checksum. " +
                    "This occurs with patched binaries, some packers, and manual PE modification.",

                "Structure" => "  Structural anomalies in the PE header suggest the binary was manually crafted or modified " +
                    "rather than produced by a standard compiler.",

                "RichHeader" => "  Rich header checksum mismatch indicates the binary's build tool metadata has been tampered with. " +
                    "Attackers modify Rich headers to impersonate different compilers or to remove attribution. " +
                    "This is also common in Microsoft's reproducible builds which modify the Rich header deterministically.",

                "Resource" => "  Elevated entropy in the resource section suggests embedded encrypted or compressed payloads. " +
                    "Dropper malware commonly hides secondary payloads (DLLs, shellcode, additional executables) in the resource section.",

                "EmbeddedPE" => "  Embedded PE executables in the resource section are a strong indicator of dropper behavior. " +
                    "The binary likely extracts and executes these embedded executables at runtime. " +
                    "MITRE ATT&CK: T1027.009 (Embedded Payloads).",

                "VersionInfo" => "  Missing version information is unusual for legitimate software. Professional applications include " +
                    "version resources with company name, product name, and file description. " +
                    "Malware and hastily compiled tools often lack this metadata.",

                "Certificate" => a.Description.Contains("Self-signed") ?
                    "  Self-signed certificates provide no trust guarantee — anyone can generate them. " +
                    "Malware frequently uses self-signed certificates to bypass basic signature checks." :
                    "  Certificate issues compromise the trust chain. Expired or revoked certificates should be treated with suspicion.",

                _ => $"  {a.Type} anomaly detected."
            };

            sb.AppendLine(explanation);
            sb.AppendLine();
        }

        // TLS callback additional detail
        if (m.HasTlsCallbacks)
            sb.AppendLine($"  NOTE: {m.TlsCallbackCount} TLS callback(s) detected. These execute before main() — review carefully.");

        // Embedded PEs
        if (m.EmbeddedPeCount > 0)
            sb.AppendLine($"  CRITICAL: {m.EmbeddedPeCount} embedded PE(s) found — strong dropper indicator.");

        return sb.ToString();
    }

    private string GenerateVerdict(ExecutableMetadata m)
    {
        var sb = new StringBuilder();
        bool trusted = m.IsSigned && m.IsSignatureValid;

        // Collect key findings
        var findings = new List<string>();
        var mitre = new List<string>();

        if (!m.IsSigned) findings.Add("Unsigned binary");
        if (m.IsSelfSigned) findings.Add("Self-signed certificate");
        if (m.IsSigned && !m.IsSignatureValid) findings.Add("Invalid digital signature");
        if (!m.HasVersionInfo) findings.Add("Missing version information");
        if (m.EmbeddedPeCount > 0) { findings.Add($"{m.EmbeddedPeCount} embedded PE(s) in resources"); mitre.Add("T1027.009 Embedded Payloads"); }
        if (m.HasTlsCallbacks) { findings.Add("TLS callbacks present"); mitre.Add("T1622 Debugger Evasion"); }

        var importCats = m.SuspiciousImports.Select(i => i.Category).Distinct().ToHashSet();
        if (importCats.Contains("ProcessInjection")) { findings.Add("Process injection APIs"); mitre.Add("T1055 Process Injection"); }
        if (importCats.Contains("AntiDebug")) { findings.Add("Anti-debug techniques"); mitre.Add("T1622 Debugger Evasion"); }
        if (importCats.Contains("Network")) { findings.Add("Network communication APIs"); mitre.Add("T1071 Application Layer Protocol"); }
        if (importCats.Contains("Cryptography")) findings.Add("Cryptographic APIs");
        if (importCats.Contains("PersistenceService")) { findings.Add("Service installation APIs"); mitre.Add("T1543.003 Windows Service"); }

        var stringCats = m.SuspiciousStrings.Select(s => s.Category).Distinct().ToHashSet();
        if (stringCats.Contains("ShellExecution")) { findings.Add("Shell command execution strings"); mitre.Add("T1059 Command Interpreter"); }
        if (stringCats.Contains("SandboxDetection")) { findings.Add("Sandbox/VM detection"); mitre.Add("T1497 Sandbox Evasion"); }
        if (stringCats.Contains("IpAddress")) findings.Add("Hardcoded IP addresses");
        if (stringCats.Contains("CredentialAccess")) { findings.Add("Credential access indicators"); mitre.Add("T1003 Credential Dumping"); }

        var highEntropySections = m.Sections.Where(s => s.IsExecutable && s.Entropy > 7.0).ToList();
        if (highEntropySections.Count > 0)
            findings.Add($"High entropy executable section(s) — possible packing");

        if (!m.IsDotNet && m.ImportCount > 0 && m.ImportCount < 10)
            findings.Add("Very low import count — possible packing or dynamic resolution");

        // Overall assessment
        sb.AppendLine("RISK ASSESSMENT:");
        sb.AppendLine($"Score: {m.RiskScore:F1}/100 — {m.RiskLevel}");
        sb.AppendLine();

        if (m.RiskLevel == "VeryLow" || m.RiskLevel == "Low")
        {
            sb.AppendLine("ASSESSMENT: This file shows no significant indicators of malicious behavior. ");
            if (trusted)
                sb.Append("The valid digital signature from a trusted publisher provides strong assurance of authenticity and integrity. ");
            if (findings.Count > 0)
            {
                sb.AppendLine($"Minor observations ({findings.Count}):");
                foreach (var f in findings) sb.AppendLine($"  • {f}");
            }
            sb.AppendLine();
            sb.AppendLine("RECOMMENDATION: Safe for execution in production environments. No further analysis required.");
        }
        else if (m.RiskLevel == "Medium")
        {
            sb.AppendLine("ASSESSMENT: This file contains multiple indicators that warrant manual review. " +
                "The combination of findings is unusual for legitimate software but not definitively malicious.");
            sb.AppendLine();
            sb.AppendLine($"Key findings ({findings.Count}):");
            foreach (var f in findings) sb.AppendLine($"  • {f}");
            sb.AppendLine();
            sb.AppendLine("RECOMMENDATION: Execute in a sandbox environment first. Submit to VirusTotal for community analysis. " +
                "Review the suspicious imports and strings manually before allowing in production.");
        }
        else if (m.RiskLevel == "High")
        {
            sb.AppendLine("ASSESSMENT: This file exhibits strong indicators of malicious behavior. " +
                "The combination of suspicious imports, strings, and structural anomalies is consistent with malware.");
            sb.AppendLine();
            sb.AppendLine($"Key findings ({findings.Count}):");
            foreach (var f in findings) sb.AppendLine($"  • {f}");
            sb.AppendLine();

            // Try to classify malware type
            sb.Append("POSSIBLE CLASSIFICATION: ");
            if (importCats.Contains("ProcessInjection") && importCats.Contains("Network"))
                sb.AppendLine("Remote Access Trojan (RAT) / Backdoor");
            else if (importCats.Contains("Cryptography") && stringCats.Contains("SuspiciousPath"))
                sb.AppendLine("Ransomware / Crypto-malware");
            else if (importCats.Contains("Network") && stringCats.Contains("ShellExecution"))
                sb.AppendLine("C2 Implant / Reverse Shell");
            else if (m.EmbeddedPeCount > 0)
                sb.AppendLine("Dropper / Loader");
            else
                sb.AppendLine("Generic Trojan / Malware");

            sb.AppendLine();
            sb.AppendLine("RECOMMENDATION: DO NOT execute outside a controlled sandbox. Quarantine the file. " +
                "Submit to VirusTotal and your organization's threat intelligence team. Investigate the source of this file.");
        }
        else
        { // Critical
            sb.AppendLine("ASSESSMENT: This file is almost certainly malicious. Multiple high-confidence indicators " +
                "are present across imports, strings, and structural analysis.");
            sb.AppendLine();
            sb.AppendLine($"Critical findings ({findings.Count}):");
            foreach (var f in findings) sb.AppendLine($"  ⚠ {f}");
            sb.AppendLine();
            sb.AppendLine("RECOMMENDATION: QUARANTINE IMMEDIATELY. Do not execute under any circumstances. " +
                "Report to your security operations team. Investigate how this file entered the environment. " +
                "Check for lateral movement and other compromised systems.");
        }

        // MITRE ATT&CK
        if (mitre.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("MITRE ATT&CK TECHNIQUES OBSERVED:");
            foreach (var t in mitre.Distinct()) sb.AppendLine($"  • {t}");
        }

        // Confidence
        sb.AppendLine();
        int confidence = CalculateConfidence(m, findings.Count);
        sb.AppendLine($"CONFIDENCE: {confidence}% — " + confidence switch
        {
            >= 90 => "Very high confidence in this assessment.",
            >= 70 => "High confidence. Key indicators are clear.",
            >= 50 => "Moderate confidence. Some indicators are ambiguous.",
            _ => "Low confidence. Limited indicators available for analysis."
        });

        return sb.ToString();
    }

    private int CalculateConfidence(ExecutableMetadata m, int findingCount)
    {
        int confidence = 40; // Baseline

        if (m.IsSigned && m.IsSignatureValid) confidence += 25; // Strong trust signal
        if (findingCount > 5) confidence += 15;
        if (findingCount > 10) confidence += 10;
        if (m.SuspiciousImports.Count > 0) confidence += 10;
        if (m.SuspiciousStrings.Count > 0) confidence += 5;
        if (m.ImportCount > 50) confidence += 5; // More data = more confidence

        return Math.Min(confidence, 98);
    }
}