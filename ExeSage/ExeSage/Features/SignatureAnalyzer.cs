using System;
using System.IO;
using System.Runtime.InteropServices;
using ExeSage.Core;

namespace ExeSage.Features;

/// <summary>
/// Validates digital signatures on PE files.
/// 1. Embedded Authenticode — WinVerifyTrust with WTD_CHOICE_FILE
/// 2. Catalog signature — hash lookup in Windows catalog store
/// Windows-only — gracefully skipped on other platforms.
/// </summary>
internal class SignatureAnalyzer {
    private const uint ERROR_SUCCESS = 0x00000000;
    private const uint TRUST_E_NOSIGNATURE = 0x800B0100;

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfoStruct;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    public void Analyze(ExecutableMetadata metadata) {
        if (metadata == null)
            throw new ArgumentNullException(nameof(metadata));

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
            metadata.IsSigned = false;
            metadata.IsSignatureValid = false;
            return;
        }

        try {
            if (CheckEmbeddedSignature(metadata))
                return;

            CheckCatalogSignature(metadata);
        }
        catch {
            if (!metadata.IsSigned) {
                metadata.IsSigned = false;
                metadata.IsSignatureValid = false;
            }
        }
    }

    private bool CheckEmbeddedSignature(ExecutableMetadata metadata) {
        var fileInfo = new WINTRUST_FILE_INFO {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = metadata.FilePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        IntPtr pFileInfo = IntPtr.Zero;
        IntPtr pTrustData = IntPtr.Zero;

        try {
            pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);

            var trustData = new WINTRUST_DATA {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2, // WTD_UI_NONE
                fdwRevocationChecks = 0,
                dwUnionChoice = 1, // WTD_CHOICE_FILE
                pInfoStruct = pFileInfo,
            };

            pTrustData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(trustData, pTrustData, false);

            Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            uint result = WinVerifyTrust(IntPtr.Zero, ref action, pTrustData);

            if (result == ERROR_SUCCESS) {
                metadata.IsSigned = true;
                metadata.IsSignatureValid = true;
                metadata.SignatureType = "Embedded";
                return true;
            }
            else if (result == TRUST_E_NOSIGNATURE) {
                return false;
            }
            else {
                metadata.IsSigned = true;
                metadata.IsSignatureValid = false;
                metadata.SignatureType = "Embedded (Invalid)";
                return true;
            }
        }
        finally {
            if (pFileInfo != IntPtr.Zero) Marshal.FreeHGlobal(pFileInfo);
            if (pTrustData != IntPtr.Zero) Marshal.FreeHGlobal(pTrustData);
        }
    }

    /// <summary>
    /// Checks if the file's hash exists in the Windows catalog store.
    /// If CryptCATAdminEnumCatalogFromHash finds a match, the file is
    /// catalog-signed. The catalog files themselves are Authenticode-signed
    /// by Microsoft and verified by Windows — finding a match means the
    /// file is trusted.
    /// </summary>
    private void CheckCatalogSignature(ExecutableMetadata metadata) {
        IntPtr hCatAdmin = IntPtr.Zero;
        IntPtr hFile = INVALID_HANDLE_VALUE;
        IntPtr hCatInfo = IntPtr.Zero;

        try {
            if (!CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0))
                return;

            hFile = CreateFileW(metadata.FilePath, 0x80000000, 0x01,
                IntPtr.Zero, 3, 0x80, IntPtr.Zero);

            if (hFile == INVALID_HANDLE_VALUE)
                return;

            // Get hash size first
            uint hashSize = 0;
            CryptCATAdminCalcHashFromFileHandle(hFile, ref hashSize, null, 0);
            if (hashSize == 0) return;

            // Calculate hash
            byte[] hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle(hFile, ref hashSize, hash, 0))
                return;

            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;

            // Look up hash in catalog store
            IntPtr prevCat = IntPtr.Zero;
            hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, ref prevCat);

            if (hCatInfo == IntPtr.Zero) {
                // Not in any catalog — truly unsigned
                metadata.IsSigned = false;
                metadata.IsSignatureValid = false;
                return;
            }

            // Found in catalog — file is catalog-signed and trusted
            metadata.IsSigned = true;
            metadata.IsSignatureValid = true;
            metadata.SignatureType = "Catalog";

            // Try to get the catalog file path for informational purposes
            var catInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0)) {
                if (!string.IsNullOrEmpty(catInfo.wszCatalogFile))
                    metadata.CatalogFile = Path.GetFileName(catInfo.wszCatalogFile);
            }
        }
        finally {
            if (hCatInfo != IntPtr.Zero && hCatAdmin != IntPtr.Zero)
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            if (hFile != INVALID_HANDLE_VALUE)
                CloseHandle(hFile);
            if (hCatAdmin != IntPtr.Zero)
                CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }
}
