// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Diagnostics;
// using System.Runtime.InteropServices;
// using System.Security;
using System.Security.Cryptography.X509Certificates;

using Internal.Cryptography.Pal.Native;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class CertificatePal : IDisposable, ICertificatePal
    {
        private static ICertificatePal FromBlobOrFile(byte[] rawData, string fileName, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
        {
            Debug.Assert(rawData != null || fileName != null);
            Debug.Assert(password != null);

            bool loadFromFile = (fileName != null);

            PfxCertStoreFlags pfxCertStoreFlags = MapKeyStorageFlags(keyStorageFlags);
            bool deleteKeyContainer = false;

            CertEncodingType msgAndCertEncodingType;
            ContentType contentType;
            FormatType formatType;
            SafeCertStoreHandle hCertStore = null;
            SafeCryptMsgHandle hCryptMsg = null;
            SafeCertContextHandle pCertContext = null;

            try
            {
                unsafe
                {
                    fixed (byte* pRawData = rawData)
                    {
                        fixed (char* pFileName = fileName)
                        {
                            CRYPTOAPI_BLOB certBlob = new CRYPTOAPI_BLOB(loadFromFile ? 0 : rawData.Length, pRawData);

                            CertQueryObjectType objectType = loadFromFile ? CertQueryObjectType.CERT_QUERY_OBJECT_FILE : CertQueryObjectType.CERT_QUERY_OBJECT_BLOB;
                            void* pvObject = loadFromFile ? (void*)pFileName : (void*)&certBlob;

                            bool success = Interop.crypt32.CryptQueryObject(
                                objectType,
                                pvObject,
                                X509ExpectedContentTypeFlags,
                                X509ExpectedFormatTypeFlags,
                                0,
                                out msgAndCertEncodingType,
                                out contentType,
                                out formatType,
                                out hCertStore,
                                out hCryptMsg,
                                out pCertContext
                                    );
                            if (!success)
                            {
                                int hr = Interop.CPError.GetHRForLastWin32Error();
                                throw hr.ToCryptographicException();
                            }
                        }
                    }

                    if (contentType == ContentType.CERT_QUERY_CONTENT_PKCS7_SIGNED || contentType == ContentType.CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED)
                    {
                        pCertContext = GetSignerInPKCS7Store(hCertStore, hCryptMsg);
                    }
                    else if (contentType == ContentType.CERT_QUERY_CONTENT_PFX)
                    {
                        if (loadFromFile)
                            rawData = File.ReadAllBytes(fileName);
                        pCertContext = FilterPFXStore(rawData, password, pfxCertStoreFlags);

                        // If PersistKeySet is set we don't delete the key, so that it persists.
                        // If EphemeralKeySet is set we don't delete the key, because there's no file, so it's a wasteful call.
                        const X509KeyStorageFlags DeleteUnless =
                            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.EphemeralKeySet |
                            // begin: gost
                            X509KeyStorageFlags.CspNoPersistKeySet;
                            // end gost

                        deleteKeyContainer = ((keyStorageFlags & DeleteUnless) == 0);
                    }

                    CertificatePal pal = new CertificatePal(pCertContext, deleteKeyContainer);
                    pCertContext = null;
                    return pal;
                }
            }
            finally
            {
                if (hCertStore != null)
                    hCertStore.Dispose();
                if (hCryptMsg != null)
                    hCryptMsg.Dispose();
                if (pCertContext != null)
                    pCertContext.Dispose();
            }
        }
    }
}
