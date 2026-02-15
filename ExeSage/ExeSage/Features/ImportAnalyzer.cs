using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using ExeSage.Core;

namespace ExeSage.Features;

/// <summary>
/// Parses PE import table and flags dangerous API usage by category.
/// Also detects .NET assemblies (which resolve APIs at runtime via CLR).
/// </summary>
internal class ImportAnalyzer {
    private static readonly Dictionary<string, (string Category, string Description)> DangerousApis = new() {
        // Process injection
        ["VirtualAllocEx"]        = ("ProcessInjection", "Allocate memory in remote process"),
        ["WriteProcessMemory"]    = ("ProcessInjection", "Write to remote process memory"),
        ["CreateRemoteThread"]    = ("ProcessInjection", "Execute code in remote process"),
        ["NtUnmapViewOfSection"]  = ("ProcessInjection", "Process hollowing technique"),
        ["RtlCreateUserThread"]   = ("ProcessInjection", "Alternative thread creation"),
        ["QueueUserAPC"]          = ("ProcessInjection", "APC injection technique"),
        ["SetThreadContext"]      = ("ProcessInjection", "Modify thread context (hollowing)"),
        ["ResumeThread"]          = ("ProcessInjection", "Resume thread after injection"),
        ["NtCreateThreadEx"]      = ("ProcessInjection", "Low-level thread creation"),

        // Memory manipulation (shellcode loading patterns)
        ["VirtualAlloc"]          = ("MemoryManipulation", "Allocate executable memory"),
        ["VirtualProtect"]        = ("MemoryManipulation", "Change memory protection (RWX)"),
        ["VirtualProtectEx"]      = ("MemoryManipulation", "Change remote memory protection"),
        ["HeapCreate"]            = ("MemoryManipulation", "Create private heap"),

        // Process creation / execution
        ["CreateProcessW"]        = ("ProcessExecution", "Create new process"),
        ["CreateProcessA"]        = ("ProcessExecution", "Create new process"),
        ["ShellExecuteW"]         = ("ProcessExecution", "Shell execute command"),
        ["ShellExecuteA"]         = ("ProcessExecution", "Shell execute command"),
        ["ShellExecuteExW"]       = ("ProcessExecution", "Shell execute (extended)"),
        ["WinExec"]               = ("ProcessExecution", "Execute command"),
        ["CreateProcessAsUserW"]  = ("ProcessExecution", "Create process as different user"),

        // Anti-debug (strong signals)
        ["CheckRemoteDebuggerPresent"]  = ("AntiDebug", "Check for remote debugger"),
        ["NtQueryInformationProcess"]   = ("AntiDebug", "Query process (detect debugger)"),
        ["NtSetInformationThread"]      = ("AntiDebug", "Hide thread from debugger"),
        ["DebugActiveProcess"]          = ("AntiDebug", "Attach as debugger"),

        // Anti-debug (weak — common in normal apps)
        ["IsDebuggerPresent"]           = ("AntiDebugWeak", "Check if debugger attached (common in normal apps)"),
        ["OutputDebugStringW"]          = ("AntiDebugWeak", "Debug output (common in normal apps)"),
        ["OutputDebugStringA"]          = ("AntiDebugWeak", "Debug output (common in normal apps)"),

        // Persistence — registry
        ["RegSetValueExW"]   = ("PersistenceRegistry", "Write registry value"),
        ["RegSetValueExA"]   = ("PersistenceRegistry", "Write registry value"),
        ["RegCreateKeyW"]    = ("PersistenceRegistry", "Create registry key"),
        ["RegCreateKeyA"]    = ("PersistenceRegistry", "Create registry key"),
        ["RegCreateKeyExW"]  = ("PersistenceRegistry", "Create registry key (extended)"),
        ["RegCreateKeyExA"]  = ("PersistenceRegistry", "Create registry key (extended)"),

        // Persistence — services
        ["CreateServiceW"]   = ("PersistenceService", "Install Windows service"),
        ["CreateServiceA"]   = ("PersistenceService", "Install Windows service"),
        ["StartServiceW"]    = ("PersistenceService", "Start Windows service"),
        ["StartServiceA"]    = ("PersistenceService", "Start Windows service"),
        ["OpenSCManagerW"]   = ("PersistenceService", "Open Service Control Manager"),
        ["OpenSCManagerA"]   = ("PersistenceService", "Open Service Control Manager"),

        // Network
        ["WSAStartup"]          = ("Network", "Initialize Winsock"),
        ["socket"]              = ("Network", "Create network socket"),
        ["connect"]             = ("Network", "Connect to remote host"),
        ["send"]                = ("Network", "Send network data"),
        ["recv"]                = ("Network", "Receive network data"),
        ["InternetOpenW"]       = ("Network", "Initialize WinINet (HTTP)"),
        ["InternetOpenA"]       = ("Network", "Initialize WinINet (HTTP)"),
        ["InternetConnectW"]    = ("Network", "Connect via HTTP/FTP"),
        ["InternetConnectA"]    = ("Network", "Connect via HTTP/FTP"),
        ["HttpSendRequestW"]    = ("Network", "Send HTTP request"),
        ["HttpSendRequestA"]    = ("Network", "Send HTTP request"),
        ["InternetReadFile"]    = ("Network", "Read HTTP response"),
        ["URLDownloadToFileW"]  = ("Network", "Download file from URL"),
        ["URLDownloadToFileA"]  = ("Network", "Download file from URL"),
        ["HttpOpenRequestW"]    = ("Network", "Open HTTP request"),
        ["HttpOpenRequestA"]    = ("Network", "Open HTTP request"),

        // Cryptography
        ["CryptEncrypt"]          = ("Cryptography", "Encrypt data"),
        ["CryptDecrypt"]          = ("Cryptography", "Decrypt data"),
        ["BCryptEncrypt"]         = ("Cryptography", "CNG crypto encrypt"),
        ["BCryptDecrypt"]         = ("Cryptography", "CNG crypto decrypt"),
        ["CryptAcquireContextW"]  = ("Cryptography", "Acquire crypto context"),
        ["CryptAcquireContextA"]  = ("Cryptography", "Acquire crypto context"),

        // File system operations (suspicious in context)
        ["DeleteFileW"]          = ("FileOperation", "Delete file"),
        ["DeleteFileA"]          = ("FileOperation", "Delete file"),
        ["MoveFileExW"]          = ("FileOperation", "Move/rename file"),
        ["CopyFileW"]            = ("FileOperation", "Copy file"),
    };

    public void Analyze(ExecutableMetadata metadata) {
        if (metadata == null)
            throw new ArgumentNullException(nameof(metadata));

        using var stream = File.OpenRead(metadata.FilePath);
        using var reader = new BinaryReader(stream, Encoding.ASCII, leaveOpen: false);

        try {
            stream.Seek(0x3C, SeekOrigin.Begin);
            uint peHeaderOffset = reader.ReadUInt32();

            stream.Seek(peHeaderOffset, SeekOrigin.Begin);
            if (reader.ReadUInt32() != 0x00004550) return;

            stream.Seek(peHeaderOffset + 4 + 20, SeekOrigin.Begin);
            ushort magic = reader.ReadUInt16();
            bool isPe32Plus = (magic == 0x020B);
            if (magic != 0x010B && magic != 0x020B) return;

            // DataDirectory offsets: PE32 +96, PE32+ +112
            int dataDirOffset = isPe32Plus ? 112 : 96;
            int importEntryOffset = dataDirOffset + (1 * 8);

            long optionalHeaderStart = peHeaderOffset + 4 + 20;
            stream.Seek(optionalHeaderStart + importEntryOffset, SeekOrigin.Begin);

            uint importDirRva = reader.ReadUInt32();
            uint importDirSize = reader.ReadUInt32();

            if (importDirRva == 0) return;

            // Check for .NET CLR directory (DataDirectory[14])
            int clrEntryOffset = dataDirOffset + (14 * 8);
            stream.Seek(optionalHeaderStart + clrEntryOffset, SeekOrigin.Begin);
            uint clrRva = reader.ReadUInt32();
            uint clrSize = reader.ReadUInt32();
            metadata.IsDotNet = (clrRva != 0 && clrSize > 0);

            long importDirFileOffset = RvaToFileOffset(importDirRva, metadata, stream);
            if (importDirFileOffset == -1) return;

            stream.Seek(importDirFileOffset, SeekOrigin.Begin);

            while (true) {
                uint originalFirstThunk = reader.ReadUInt32();
                reader.ReadUInt32(); // TimeDateStamp
                reader.ReadUInt32(); // ForwarderChain
                uint nameRva = reader.ReadUInt32();
                uint firstThunk = reader.ReadUInt32();

                if (originalFirstThunk == 0 && nameRva == 0) break;

                string dllName = ReadStringAtRva(nameRva, metadata, stream, reader);
                if (string.IsNullOrEmpty(dllName)) continue;

                metadata.ImportedDlls.Add(dllName);

                if (originalFirstThunk != 0)
                    ReadImportNames(originalFirstThunk, dllName, isPe32Plus, metadata, stream, reader);
            }
        }
        catch {
            // Graceful degradation — return partial results
        }
    }

    private void ReadImportNames(uint intRva, string dllName, bool isPe32Plus,
        ExecutableMetadata metadata, Stream stream, BinaryReader reader) {

        long intOffset = RvaToFileOffset(intRva, metadata, stream);
        if (intOffset == -1) return;

        long savedPos = stream.Position;
        stream.Seek(intOffset, SeekOrigin.Begin);

        int ptrSize = isPe32Plus ? 8 : 4;

        while (true) {
            ulong entry = ptrSize == 8 ? reader.ReadUInt64() : reader.ReadUInt32();
            if (entry == 0) break;

            bool isByOrdinal = ptrSize == 8
                ? (entry & 0x8000000000000000) != 0
                : (entry & 0x80000000) != 0;

            if (isByOrdinal) {
                ushort ordinal = (ushort)(entry & 0xFFFF);
                metadata.ImportedFunctions.Add($"{dllName}!Ordinal_{ordinal}");
                metadata.ImportCount++;
            }
            else {
                uint nameRva = (uint)(entry & 0x7FFFFFFF);
                string funcName = ReadFunctionName(nameRva, metadata, stream, reader);

                if (!string.IsNullOrEmpty(funcName)) {
                    string fullName = $"{dllName}!{funcName}";
                    metadata.ImportedFunctions.Add(fullName);
                    metadata.ImportCount++;

                    if (DangerousApis.TryGetValue(funcName, out var apiInfo)) {
                        metadata.SuspiciousImports.Add(new SuspiciousImport {
                            FunctionName = fullName,
                            Category = apiInfo.Category,
                            Description = apiInfo.Description
                        });
                    }
                }
            }
        }

        stream.Seek(savedPos, SeekOrigin.Begin);
    }

    private string ReadFunctionName(uint rva, ExecutableMetadata metadata, Stream stream, BinaryReader reader) {
        long offset = RvaToFileOffset(rva, metadata, stream);
        if (offset == -1) return null;

        long savedPos = stream.Position;
        stream.Seek(offset, SeekOrigin.Begin);
        reader.ReadUInt16(); // Hint

        var bytes = new List<byte>();
        byte b;
        while ((b = reader.ReadByte()) != 0 && bytes.Count < 256)
            bytes.Add(b);

        stream.Seek(savedPos, SeekOrigin.Begin);
        return Encoding.ASCII.GetString(bytes.ToArray());
    }

    private string ReadStringAtRva(uint rva, ExecutableMetadata metadata, Stream stream, BinaryReader reader) {
        if (rva == 0) return null;

        long offset = RvaToFileOffset(rva, metadata, stream);
        if (offset == -1) return null;

        long savedPos = stream.Position;
        stream.Seek(offset, SeekOrigin.Begin);

        var bytes = new List<byte>();
        byte b;
        while ((b = reader.ReadByte()) != 0 && bytes.Count < 256)
            bytes.Add(b);

        stream.Seek(savedPos, SeekOrigin.Begin);
        return Encoding.ASCII.GetString(bytes.ToArray());
    }

    private long RvaToFileOffset(uint rva, ExecutableMetadata metadata, Stream stream) {
        if (metadata.Sections == null) return -1;

        foreach (var section in metadata.Sections) {
            uint sectionEnd = section.VirtualAddress + section.VirtualSize;
            if (rva >= section.VirtualAddress && rva < sectionEnd)
                return section.PointerToRawData + (rva - section.VirtualAddress);
        }

        return -1;
    }
}
