// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

using Internal.Cryptography.Pal.Native;

using SafeNCryptKeyHandle = Microsoft.Win32.SafeHandles.SafeNCryptKeyHandle;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class CertificatePal : IDisposable, ICertificatePal
    {

        // begin: gost
        public unsafe void SetCspPrivateKey(AsymmetricAlgorithm key)
        {
            if (key == null)
            {
                return;
            }
            CspKeyContainerInfo keyContainerInfo;
            switch (key.SignatureAlgorithm)
            {
                case GostConstants.XmlSignatureAlgorithm2001:
                {
                    Gost3410CryptoServiceProvider asymmetricAlgorithm = key as Gost3410CryptoServiceProvider;
                    keyContainerInfo = asymmetricAlgorithm.CspKeyContainerInfo;
                    break;
                }
                case GostConstants.XmlSignatureAlgorithm2012_256:
                {
                    Gost3410_2012_256CryptoServiceProvider asymmetricAlgorithm = key as Gost3410_2012_256CryptoServiceProvider;
                    keyContainerInfo = asymmetricAlgorithm.CspKeyContainerInfo;
                    break;
                }
                case GostConstants.XmlSignatureAlgorithm2012_512:
                {
                    Gost3410_2012_512CryptoServiceProvider asymmetricAlgorithm = key as Gost3410_2012_512CryptoServiceProvider;
                    keyContainerInfo = asymmetricAlgorithm.CspKeyContainerInfo;
                    break;
                }
                case "RSA":
                {
                    RSACryptoServiceProvider asymmetricAlgorithm = key as RSACryptoServiceProvider;
                    keyContainerInfo = asymmetricAlgorithm.CspKeyContainerInfo;
                    break;
                }
                case "DSA":
                {
                    DSACryptoServiceProvider asymmetricAlgorithm = key as DSACryptoServiceProvider;
                    keyContainerInfo = asymmetricAlgorithm.CspKeyContainerInfo;
                    break;
                }
                default:
                {
                    throw new PlatformNotSupportedException();
                }
            }

            SafeLocalAllocHandle ptr = SafeLocalAllocHandle.InvalidHandle;

            fixed (char* keyContainerName = keyContainerInfo.KeyContainerName)
            fixed (char* providerName = keyContainerInfo.ProviderName)
            {
                CRYPT_KEY_PROV_INFO keyProvInfo = new CRYPT_KEY_PROV_INFO();
                keyProvInfo.pwszContainerName = keyContainerName;
                keyProvInfo.pwszProvName = providerName;
                keyProvInfo.dwProvType = keyContainerInfo.ProviderType;
                keyProvInfo.dwFlags = keyContainerInfo.MachineKeyStore 
                    ? CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET 
                    : CryptAcquireContextFlags.None;
                keyProvInfo.cProvParam = 0;
                keyProvInfo.rgProvParam = IntPtr.Zero;
                keyProvInfo.dwKeySpec = (int)keyContainerInfo.KeyNumber;

                if (!Interop.crypt32.CertSetCertificateContextProperty(
                    _certContext,
                    CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID,
                    CertSetPropertyFlags.None,
                    &keyProvInfo))
                {
                    throw Marshal.GetLastWin32Error().ToCryptographicException();
                }
            }
        }
        // end: gost

        //
        // Returns the private key referenced by a store certificate. Note that despite the return type being declared "CspParameters",
        // the key can actually be a CNG key. To distinguish, examine the ProviderType property. If it is 0, this key is a CNG key with
        // the various properties of CspParameters being "repurposed" into storing CNG info. 
        // 
        // This is a behavior this method inherits directly from the Crypt32 CRYPT_KEY_PROV_INFO semantics.
        //
        // It would have been nice not to let this ugliness escape out of this helper method. But X509Certificate2.ToString() calls this 
        // method too so we cannot just change it without breaking its output.
        // 
        private CspParameters GetPrivateKeyCsp()
        {
            int cbData = 0;
            if (!Interop.crypt32.CertGetCertificateContextProperty(_certContext, CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID, null, ref cbData))
            {
                int dwErrorCode = Marshal.GetLastWin32Error();
                if (dwErrorCode == ErrorCode.CRYPT_E_NOT_FOUND)
                    return null;
                throw dwErrorCode.ToCryptographicException();
            }

            unsafe
            {
                byte[] privateKey = new byte[cbData];
                fixed (byte* pPrivateKey = privateKey)
                {
                    if (!Interop.crypt32.CertGetCertificateContextProperty(_certContext, CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID, privateKey, ref cbData))
                        throw Marshal.GetLastWin32Error().ToCryptographicException();
                    CRYPT_KEY_PROV_INFO* pKeyProvInfo = (CRYPT_KEY_PROV_INFO*)pPrivateKey;

                    CspParameters cspParameters = new CspParameters();
                    cspParameters.ProviderName = Marshal.PtrToStringUni((IntPtr)(pKeyProvInfo->pwszProvName));
                    cspParameters.KeyContainerName = Marshal.PtrToStringUni((IntPtr)(pKeyProvInfo->pwszContainerName));
                    cspParameters.ProviderType = pKeyProvInfo->dwProvType;
                    cspParameters.KeyNumber = pKeyProvInfo->dwKeySpec;
                    cspParameters.Flags = (CspProviderFlags)((pKeyProvInfo->dwFlags & CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET) == CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET ? CspProviderFlags.UseMachineKeyStore : 0);
                    return cspParameters;
                }
            }
        }

        // begin: gost
        /// <summary>
        /// Get non-persist certificate private key from CERT_KEY_CONTEXT_PROP_ID
        /// </summary>
        /// <returns></returns>
        private (IntPtr hprov, int keySpec) GetNonPersistPrivateKeyCsp()
        {
            int cbData = 0;

            if (!Interop.crypt32.CertGetCertificateContextProperty(_certContext, CertContextPropId.CERT_KEY_CONTEXT_PROP_ID, null, ref cbData))
            {
                int dwErrorCode = Marshal.GetLastWin32Error();
                if (dwErrorCode == ErrorCode.CRYPT_E_NOT_FOUND)
                    return (IntPtr.Zero, 0);
                throw dwErrorCode.ToCryptographicException();
            }
            unsafe
            {
                byte[] privateKey = new byte[cbData];
                fixed (byte* pPrivateKey = privateKey)
                {
                    if (!Interop.crypt32.CertGetCertificateContextProperty(_certContext, CertContextPropId.CERT_KEY_CONTEXT_PROP_ID, privateKey, ref cbData))
                        throw Marshal.GetLastWin32Error().ToCryptographicException();
                    CERT_KEY_CONTEXT* pKeyProvInfo = (CERT_KEY_CONTEXT*)pPrivateKey;

                    return (pKeyProvInfo->hCryptProv, (int)pKeyProvInfo->dwKeySpec);
                }
            }
        }
        // end: gost

        private unsafe ICertificatePal CopyWithPersistedCapiKey(CspKeyContainerInfo keyContainerInfo)
        {
            if (string.IsNullOrEmpty(keyContainerInfo.KeyContainerName))
            {
                return null;
            }

            // Make a new pal from bytes.
            CertificatePal pal = (CertificatePal)FromBlob(RawData, SafePasswordHandle.InvalidHandle, X509KeyStorageFlags.PersistKeySet);
            CRYPT_KEY_PROV_INFO keyProvInfo = new CRYPT_KEY_PROV_INFO();

            fixed (char* keyName = keyContainerInfo.KeyContainerName)
            fixed (char* provName = keyContainerInfo.ProviderName)
            {
                keyProvInfo.pwszContainerName = keyName;
                keyProvInfo.pwszProvName = provName;
                keyProvInfo.dwFlags = keyContainerInfo.MachineKeyStore ? CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET : 0;
                keyProvInfo.dwProvType = keyContainerInfo.ProviderType;
                keyProvInfo.dwKeySpec = (int)keyContainerInfo.KeyNumber;

                if (!Interop.crypt32.CertSetCertificateContextProperty(
                    pal._certContext,
                    CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID,
                    CertSetPropertyFlags.None,
                    &keyProvInfo))
                {
                    pal.Dispose();
                    throw Marshal.GetLastWin32Error().ToCryptographicException();
                }
            }

            return pal;
        }
    }
}
