using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

using Internal.Cryptography;
using Internal.Cryptography.Pal.Native;

internal static partial class Interop
{
    public static partial class crypt32
    {
        public static unsafe string CertGetNameString(
            SafeCertContextHandle certContext,
            CertNameType certNameType,
            CertNameFlags certNameFlags,
            CertNameStringType strType)
        {
            const int sizeof_wchar_t = 4;
            int cchCount = CertGetNameString(certContext, certNameType, certNameFlags, strType, null, 0);
            if (cchCount == 0)
            {
                throw Interop.CPError.GetLastWin32Error().ToCryptographicException();
            }

            Span<byte> buffer = cchCount <= 256 ? stackalloc byte[cchCount*sizeof_wchar_t] : new byte[cchCount*sizeof_wchar_t];
            fixed (byte* ptr = &MemoryMarshal.GetReference(buffer))
            {
                if (CertGetNameString(certContext, certNameType, certNameFlags, strType, ptr, cchCount) == 0)
                {
                    throw Interop.CPError.GetLastWin32Error().ToCryptographicException();
                }

                Debug.Assert(buffer[(cchCount - 1)*sizeof_wchar_t] == '\0');
                // return new string(buffer.Slice(0, cchCount - 1));
                return System.Text.Encoding.UTF32.GetString(buffer.Slice(0, (cchCount-1)*sizeof_wchar_t).ToArray());
            }
        }


        [DllImport(Libraries.Crypt32, CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CertGetNameStringW")]
        private static extern unsafe int CertGetNameString(SafeCertContextHandle pCertContext, CertNameType dwType, CertNameFlags dwFlags, in CertNameStringType pvTypePara, byte* pszNameString, int cchNameString);
    }
}