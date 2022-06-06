using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.Xml;
using static Interop.Crypt32;

namespace Internal.Cryptography.Pal.Windows
{
    internal static partial class HelpersWindows
    {
        public static SubjectIdentifier ToSubjectIdentifier(this CERT_ID certId)
        {
            switch (certId.dwIdChoice)
            {
                case CertIdChoice.CERT_ID_ISSUER_SERIAL_NUMBER:
                {
                    const int dwStrType = (int)(CertNameStrTypeAndFlags.CERT_X500_NAME_STR | CertNameStrTypeAndFlags.CERT_NAME_STR_REVERSE_FLAG);

                    string issuer;
                    unsafe
                    {
                        DATA_BLOB* dataBlobPtr = &certId.u.IssuerSerialNumber.Issuer;

                        int nc = Interop.Crypt32.CertNameToStr((int)MsgEncodingType.All, dataBlobPtr, dwStrType, null, 0);
                        if (nc <= 1) // The API actually return 1 when it fails; which is not what the documentation says.
                        {
                            throw Interop.CPError.GetLastWin32Error().ToCryptographicException();
                        }

                        Span<char> name = nc <= 128 ? stackalloc char[128] : new char[nc];
                        fixed (char* namePtr = name)
                        {
                            nc = Interop.Crypt32.CertNameToStr((int)MsgEncodingType.All, dataBlobPtr, dwStrType, namePtr, nc);
                            if (nc <= 1) // The API actually return 1 when it fails; which is not what the documentation says.
                            {
                                throw Interop.CPError.GetLastWin32Error().ToCryptographicException();
                            }

                            issuer = new string(namePtr);
                        }
                    }

                    byte[] serial = certId.u.IssuerSerialNumber.SerialNumber.ToByteArray();
                    X509IssuerSerial issuerSerial = new X509IssuerSerial(issuer, serial.ToSerialString());
                    return new SubjectIdentifier(SubjectIdentifierType.IssuerAndSerialNumber, issuerSerial);
                }

                case CertIdChoice.CERT_ID_KEY_IDENTIFIER:
                {
                    byte[] ski = certId.u.KeyId.ToByteArray();
                    return new SubjectIdentifier(SubjectIdentifierType.SubjectKeyIdentifier, ski.ToSkiString());
                }

                default:
                    throw new CryptographicException(SR.Format(SR.Cryptography_Cms_Invalid_Subject_Identifier_Type, certId.dwIdChoice));
            }
        }
    }
}
