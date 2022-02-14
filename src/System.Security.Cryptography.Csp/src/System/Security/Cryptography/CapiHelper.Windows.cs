// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;
using static Interop.Crypt32;
using CryptProvParam = Interop.Advapi32.CryptProvParam;

namespace Internal.NativeCrypto
{
    /// <summary>
    /// Following part of CAPIHelper keeps the wrappers for all the PInvoke calls
    /// </summary>
    internal static partial class CapiHelper
    {
        private static readonly byte[] s_RgbPubKey =
        {
                0x06, 0x02, 0x00, 0x00, 0x00, 0xa4, 0x00, 0x00,
                0x52, 0x53, 0x41, 0x31, 0x00, 0x02, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0xab, 0xef, 0xfa, 0xc6,
                0x7d, 0xe8, 0xde, 0xfb, 0x68, 0x38, 0x09, 0x92,
                0xd9, 0x42, 0x7e, 0x6b, 0x89, 0x9e, 0x21, 0xd7,
                0x52, 0x1c, 0x99, 0x3c, 0x17, 0x48, 0x4e, 0x3a,
                0x44, 0x02, 0xf2, 0xfa, 0x74, 0x57, 0xda, 0xe4,
                0xd3, 0xc0, 0x35, 0x67, 0xfa, 0x6e, 0xdf, 0x78,
                0x4c, 0x75, 0x35, 0x1c, 0xa0, 0x74, 0x49, 0xe3,
                0x20, 0x13, 0x71, 0x35, 0x65, 0xdf, 0x12, 0x20,
                0xf5, 0xf5, 0xf5, 0xc1
        };

        /// <summary>
        /// Check to see if a better CSP than the one requested is available
        /// RSA providers are supersets of each other in the following order:
        ///    1. MS_ENH_RSA_AES_PROV
        ///    2. MS_ENHANCED_PROV
        ///    3. MS_DEF_PROV
        ///
        /// This will return the best provider which is a superset of wszProvider,
        /// or NULL if there is no upgrade available on the machine.
        /// </summary>
        /// <param name="dwProvType">Provider type</param>
        /// <param name="wszProvider">Provider name</param>
        /// <returns>Returns upgrade CSP name</returns>
        public static string UpgradeRSA(int dwProvType, string wszProvider)
        {
            bool requestedEnhanced = string.Equals(wszProvider, MS_ENHANCED_PROV, StringComparison.Ordinal);
            bool requestedBase = string.Equals(wszProvider, MS_DEF_PROV, StringComparison.Ordinal);
            string wszUpgrade = null;
            if (requestedBase || requestedEnhanced)
            {
                SafeProvHandle safeProvHandle;

                // attempt to use the AES provider
                if (S_OK == AcquireCryptContext(out safeProvHandle, null, MS_ENH_RSA_AES_PROV,
                                                dwProvType, (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT))
                {
                    wszUpgrade = MS_ENH_RSA_AES_PROV;
                }

                safeProvHandle.Dispose();
            }

            return wszUpgrade;
        }

        /// <summary>
        /// Find the default provider name to be used in the case that we
        /// were not actually passed in a provider name. The main purpose
        /// of this code is really to deal with the enhanced/default provider
        /// problems given to us by CAPI.
        /// </summary>
        /// <param name="dwType">Type of the provider</param>
        /// <returns>Name of the provider to be used</returns>
        internal static string GetDefaultProvider(int dwType)
        {
            int sizeofProviderName = 0;
            //Get the size of the provider name
            if (!Interop.Advapi32.CryptGetDefaultProvider(dwType, IntPtr.Zero,
                                                Interop.Advapi32.GetDefaultProviderFlags.CRYPT_MACHINE_DEFAULT,
                                                null, ref sizeofProviderName))
            {
                throw GetErrorCode().ToCryptographicException();
            }
            //allocate memory for the provider name
            StringBuilder providerName = new StringBuilder((int)sizeofProviderName);

            //Now call the function CryptGetDefaultProvider again to get the name of the provider
            if (!Interop.Advapi32.CryptGetDefaultProvider(dwType, IntPtr.Zero,
                                                Interop.Advapi32.GetDefaultProviderFlags.CRYPT_MACHINE_DEFAULT,
                                                providerName, ref sizeofProviderName))
            {
                throw GetErrorCode().ToCryptographicException();
            }

            // check to see if there are upgrades available for the requested CSP
            string providerNameString = providerName.ToString();
            string wszUpgrade = null;
            if (dwType == (int)ProviderType.PROV_RSA_FULL)
            {
                wszUpgrade = UpgradeRSA(dwType, providerNameString);
            }
            else if (dwType == (int)ProviderType.PROV_DSS_DH)
            {
                wszUpgrade = UpgradeDSS(dwType, providerNameString);
            }

            return wszUpgrade != null ?
                wszUpgrade : // Overwrite the provider name with the upgraded provider name
                providerNameString;
        }

        /// <summary>
        /// Creates a new key container
        /// </summary>
        private static void CreateCSP(CspParameters parameters, bool randomKeyContainer, out SafeProvHandle safeProvHandle)
        {
            uint dwFlags = (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_NEWKEYSET;
            switch (parameters.ProviderType)
            {
                case (int)CspAlgorithmType.Gost2001:
                case (int)CspAlgorithmType.Gost2012_256:
                case (int)CspAlgorithmType.Gost2012_512:
                {
                    // Gost does not support creating and using new keys in CRYPT_VERIFYCONTEXT
                    break;
                }
                default:
                {
                    if (randomKeyContainer)
                    {
                        dwFlags |= (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT;
                    }
                    break;
                }
            }

            SafeProvHandle hProv;
            int ret = OpenCSP(parameters, dwFlags, out hProv);
            if (S_OK != ret)
            {
                hProv.Dispose();
                throw ret.ToCryptographicException();
            }
            safeProvHandle = hProv;
        }

        /// <summary>
        /// Acquire a handle to a crypto service provider and optionally a key container
        /// This function implements the WszCryptAcquireContext_SO_TOLERANT
        /// </summary>
        private static int AcquireCryptContext(out SafeProvHandle safeProvHandle, string keyContainer,
                                                string providerName, int providerType, uint flags)
        {
            const uint VerifyContextFlag = (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT;
            const uint MachineContextFlag = (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET;

            int ret = S_OK;
            // Specifying both verify context (for an ephemeral key) and machine keyset (for a persisted machine key)
            // does not make sense.  Additionally, Windows is beginning to lock down against uses of MACHINE_KEYSET
            // (for instance in the app container), even if verify context is present.   Therefore, if we're using
            // an ephemeral key, strip out MACHINE_KEYSET from the flags.
            if (((flags & VerifyContextFlag) == VerifyContextFlag) &&
                ((flags & MachineContextFlag) == MachineContextFlag))
            {
                flags &= ~MachineContextFlag;
            }
            //Do not throw in this function. Just return the error code
            if (!Interop.Advapi32.CryptAcquireContext(out safeProvHandle, keyContainer, providerName, providerType, flags))
            {
                ret = GetErrorCode();
            }

            return ret;
        }

        /// <summary>
        /// This method opens the CSP using CRYPT_VERIFYCONTEXT
        /// KeyContainer must be null for the flag CRYPT_VERIFYCONTEXT
        /// This method asserts if keyContainer is not null
        /// </summary>
        /// <param name="cspParameters">CSPParameter to use</param>
        /// <param name="safeProvHandle">Safe provider handle</param>
        internal static void AcquireCsp(CspParameters cspParameters, out SafeProvHandle safeProvHandle)
        {
            Debug.Assert(cspParameters != null);
            Debug.Assert(cspParameters.KeyContainerName == null);

            SafeProvHandle hProv;
            //
            // We want to just open this CSP.  Passing in verify context will
            // open it and, if a container is given, map to open the container.
            //
            int ret = OpenCSP(cspParameters, (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT, out hProv);
            if (S_OK != ret)
            {
                hProv.Dispose();
                throw ret.ToCryptographicException();
            }

            safeProvHandle = hProv;
        }

        /// <summary>
        /// OpenCSP performs the core work of opening and creating CSPs and containers in CSPs
        /// </summary>
        public static int OpenCSP(CspParameters cspParameters, uint flags, out SafeProvHandle safeProvHandle)
        {
            string providerName = null;
            string containerName = null;
            if (null == cspParameters)
            {
                throw new ArgumentException(SR.Format(SR.CspParameter_invalid, nameof(cspParameters)));
            }

            //look for provider type in the cspParameters
            int providerType = cspParameters.ProviderType;

            //look for provider name in the cspParamters 
            //if CSP provider is not null then use the provider name from cspParameters
            if (null != cspParameters.ProviderName)
            {
                providerName = cspParameters.ProviderName;
            }
            else //Get the default provider name
            {
                providerName = GetDefaultProvider(providerType);
                cspParameters.ProviderName = providerName;
            }
            // look to see if the user specified that we should pass
            // CRYPT_MACHINE_KEYSET to CAPI to use machine key storage instead
            // of user key storage
            int cspProviderFlags = (int)cspParameters.Flags;

            // If the user specified CSP_PROVIDER_FLAGS_USE_DEFAULT_KEY_CONTAINER,
            // then ignore the key container name and hand back the default container
            if (!IsFlagBitSet((uint)cspProviderFlags, (uint)CspProviderFlags.UseDefaultKeyContainer))
            {
                //look for key container name in the cspParameters 
                if (null != cspParameters.KeyContainerName)
                {
                    containerName = cspParameters.KeyContainerName;
                }
            }

            SafeProvHandle hProv;

            // Go ahead and try to open the CSP.  If we fail, make sure the CSP
            // returned is 0 as that is going to be the error check in the caller.
            flags |= MapCspProviderFlags((int)cspParameters.Flags);
            int hr = AcquireCryptContext(out hProv, containerName, providerName, providerType, flags);
            if (hr != S_OK)
            {
                hProv.Dispose();
                safeProvHandle = SafeProvHandle.InvalidHandle;
                return hr;
            }

            hProv.ContainerName = containerName;
            hProv.ProviderName = providerName;
            hProv.Types = providerType;
            hProv.Flags = flags;

            // We never want to delete a key container if it's already there.
            if (IsFlagBitSet(flags, (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT))
            {
                hProv.PersistKeyInCsp = false;
            }

            safeProvHandle = hProv;
            return S_OK;
        }

        /// <summary>
        /// This method acquires CSP and returns the handle of CSP 
        /// </summary>
        /// <param name="parameters">Accepts the CSP Parameters</param>
        /// <param name="randomKeyContainer">Bool to indicate if key needs to be persisted</param>
        /// <returns>Returns the safehandle of CSP </returns>
        internal static SafeProvHandle CreateProvHandle(CspParameters parameters, bool randomKeyContainer)
        {
            SafeProvHandle safeProvHandle;
            uint flag = 0;
            uint hr = unchecked((uint)OpenCSP(parameters, flag, out safeProvHandle));
            //Open container failed 
            if (hr != S_OK)
            {
                safeProvHandle.Dispose();
                // If UseExistingKey flag is used and the key container does not exist
                // throw an exception without attempting to create the container.
                if (IsFlagBitSet((uint)parameters.Flags, (uint)CspProviderFlags.UseExistingKey) ||
                                                        ((hr != (uint)CryptKeyError.NTE_KEYSET_NOT_DEF && hr !=
                                                        (uint)CryptKeyError.NTE_BAD_KEYSET && hr !=
                                                        (uint)CryptKeyError.NTE_FILENOTFOUND && hr !=
                                                        // add: gost
                                                        unchecked((uint)GostConstants.SCARD_W_CANCELLED_BY_USER))))
                                                        // end: gost
                {
                    throw ((int)hr).ToCryptographicException();
                }

                //Create a new CSP. This method throws exception on failure
                CreateCSP(parameters, randomKeyContainer, out safeProvHandle);
            }

            if (parameters.ParentWindowHandle != IntPtr.Zero)
            {
                IntPtr parentWindowHandle = parameters.ParentWindowHandle;

                if (!Interop.Advapi32.CryptSetProvParam(safeProvHandle, CryptProvParam.PP_CLIENT_HWND, ref parentWindowHandle, 0))
                {
                    throw GetErrorCode().ToCryptographicException();
                }
            }

            if (parameters.KeyPassword != null)
            {
                IntPtr password = Marshal.SecureStringToCoTaskMemAnsi(parameters.KeyPassword);
                try
                {
                    CryptProvParam param =
                        (parameters.KeyNumber == (int)Interop.Advapi32.KeySpec.AT_SIGNATURE) ?
                            CryptProvParam.PP_SIGNATURE_PIN :
                            CryptProvParam.PP_KEYEXCHANGE_PIN;
                    if (!Interop.Advapi32.CryptSetProvParam(safeProvHandle, param, password, 0))
                    {
                        throw GetErrorCode().ToCryptographicException();
                    }
                }
                finally
                {
                    if (password != IntPtr.Zero)
                    {
                        Marshal.ZeroFreeCoTaskMemAnsi(password);
                    }
                }
            }

            return safeProvHandle;
        }

        /// <summary>
        /// This method validates the flag bits set or not. Only works for flags with just one bit set
        /// </summary>
        /// <param name="dwImp">int where you want to check the flag bits</param>
        /// <param name="flag">Actual flag</param>
        /// <returns>true if bits are set or false</returns>
        internal static bool IsFlagBitSet(uint dwImp, uint flag)
        {
            return (dwImp & flag) == flag;
        }

        /// <summary>
        /// This method helps reduce the duplicate code in the GetProviderParameter method
        /// </summary>
        internal static int GetProviderParameterWorker(SafeProvHandle safeProvHandle, byte[] impType, ref int cb, CryptProvParam flags)
        {
            int impTypeReturn = 0;
            if (!Interop.Advapi32.CryptGetProvParam(safeProvHandle, flags, impType, ref cb))
            {
                throw GetErrorCode().ToCryptographicException();
            }
            if (null != impType && cb == Constants.SIZE_OF_DWORD)
            {
                impTypeReturn = BitConverter.ToInt32(impType, 0);
            }
            return impTypeReturn;
        }

        /// <summary>
        /// This method queries the key container and get some of it's properties. 
        /// Those properties should never cause UI to display. 
        /// </summary>                
        public static object GetProviderParameter(SafeProvHandle safeProvHandle, int keyNumber, int keyParam)
        {
            VerifyValidHandle(safeProvHandle);
            byte[] impType = new byte[Constants.SIZE_OF_DWORD];
            int cb = sizeof(byte) * Constants.SIZE_OF_DWORD;
            SafeKeyHandle safeKeyHandle = SafeKeyHandle.InvalidHandle;
            int impTypeReturn = 0;
            int returnType = 0; //using 0 for bool and 1 for string return types
            bool retVal = false;
            string retStr = null;

            try
            {
                switch (keyParam)
                {
                    case Constants.CLR_EXPORTABLE:
                    {
                        impTypeReturn = GetProviderParameterWorker(safeProvHandle, impType, ref cb, CryptProvParam.PP_IMPTYPE);
                        //If implementation type is not HW
                        if (!IsFlagBitSet((uint)impTypeReturn, (uint)CryptGetProvParamPPImpTypeFlags.CRYPT_IMPL_HARDWARE))
                        {
                            if (!CryptGetUserKey(safeProvHandle, keyNumber, out safeKeyHandle))
                            {
                                throw GetErrorCode().ToCryptographicException();
                            }
                            byte[] permissions = null;
                            int permissionsReturn = 0;
                            permissions = new byte[Constants.SIZE_OF_DWORD];
                            cb = sizeof(byte) * Constants.SIZE_OF_DWORD;
                            if (!Interop.Advapi32.CryptGetKeyParam(safeKeyHandle, Interop.Advapi32.CryptGetKeyParamFlags.KP_PERMISSIONS, permissions, ref cb, 0))
                            {
                                throw GetErrorCode().ToCryptographicException();
                            }
                            permissionsReturn = BitConverter.ToInt32(permissions, 0);
                            retVal = IsFlagBitSet((uint)permissionsReturn, (uint)Interop.Advapi32.CryptGetKeyParamFlags.CRYPT_EXPORT);
                        }
                        else
                        {
                            //Assumption HW keys are not exportable.
                            retVal = false;
                        }

                        break;
                    }
                    case Constants.CLR_REMOVABLE:
                    {
                        impTypeReturn = GetProviderParameterWorker(safeProvHandle, impType, ref cb, CryptProvParam.PP_IMPTYPE);
                        retVal = IsFlagBitSet((uint)impTypeReturn, (uint)CryptGetProvParamPPImpTypeFlags.CRYPT_IMPL_REMOVABLE);
                        break;
                    }
                    case Constants.CLR_HARDWARE:
                    case Constants.CLR_PROTECTED:
                    {
                        impTypeReturn = GetProviderParameterWorker(safeProvHandle, impType, ref cb, CryptProvParam.PP_IMPTYPE);
                        retVal = IsFlagBitSet((uint)impTypeReturn, (uint)CryptGetProvParamPPImpTypeFlags.CRYPT_IMPL_HARDWARE);
                        break;
                    }
                    case Constants.CLR_ACCESSIBLE:
                    {
                        retVal = CryptGetUserKey(safeProvHandle, keyNumber, out safeKeyHandle) ? true : false;
                        break;
                    }
                    case Constants.CLR_UNIQUE_CONTAINER:
                    {
                        returnType = 1;
                        byte[] pb = null;
                        impTypeReturn = GetProviderParameterWorker(safeProvHandle, pb, ref cb, CryptProvParam.PP_UNIQUE_CONTAINER);
                        pb = new byte[cb];
                        impTypeReturn = GetProviderParameterWorker(safeProvHandle, pb, ref cb, CryptProvParam.PP_UNIQUE_CONTAINER);
                        // GetProviderParameterWorker allocated the null character, we want to not interpret that.
                        Debug.Assert(cb > 0);
                        Debug.Assert(pb[cb - 1] == 0);
                        retStr = Encoding.ASCII.GetString(pb, 0, cb - 1);
                        break;
                    }
                    default:
                    {
                        Debug.Fail($"Unexpected key param {keyParam}");
                        break;
                    }
                }
            }
            finally
            {
                safeKeyHandle.Dispose();
            }

            Debug.Assert(returnType == 0 || returnType == 1);
            return returnType == 0 ? (object)retVal : retStr;
        }

        /// <summary>
        /// Retrieves the handle for user public / private key pair. 
        /// </summary>
        internal static int GetUserKey(SafeProvHandle safeProvHandle, int keySpec, out SafeKeyHandle safeKeyHandle)
        {
            int hr = S_OK;
            VerifyValidHandle(safeProvHandle);
            if (!CryptGetUserKey(safeProvHandle, keySpec, out safeKeyHandle))
            {
                hr = GetErrorCode();
            }
            if (hr == S_OK)
            {
                safeKeyHandle.KeySpec = keySpec;
            }
            return hr;
        }

        /// <summary>
        /// Generates the key if provided CSP handle is valid 
        /// </summary>
        internal static int GenerateKey(SafeProvHandle safeProvHandle, int algID, int flags, uint keySize, out SafeKeyHandle safeKeyHandle)
        {
            int hr = S_OK;
            VerifyValidHandle(safeProvHandle);
            int capiFlags = (int)((uint)MapCspKeyFlags(flags) | ((uint)keySize << 16));
            if (!CryptGenKey(safeProvHandle, algID, capiFlags, out safeKeyHandle))
            {
                hr = GetErrorCode();
            }
            if (hr != S_OK)
            {
                throw GetErrorCode().ToCryptographicException();
            }

            safeKeyHandle.KeySpec = algID;
            return hr;
        }

        /// <summary>
        /// Maps CspProviderFlags enumeration into CAPI flags.
        /// </summary>
        internal static int MapCspKeyFlags(int flags)
        {
            int capiFlags = 0;
            if (!IsFlagBitSet((uint)flags, (uint)CspProviderFlags.UseNonExportableKey))
            {
                capiFlags |= (int)CryptGenKeyFlags.CRYPT_EXPORTABLE;
            }

            if (IsFlagBitSet((uint)flags, (uint)CspProviderFlags.UseArchivableKey))
            {
                capiFlags |= (int)CryptGenKeyFlags.CRYPT_ARCHIVABLE;
            }

            if (IsFlagBitSet((uint)flags, (uint)CspProviderFlags.UseUserProtectedKey))
            {
                capiFlags |= (int)CryptGenKeyFlags.CRYPT_USER_PROTECTED;
            }

            return capiFlags;
        }

        /// <summary>
        ///Maps CspProviderFlags enumeration into CAPI flags
        /// </summary>
        internal static uint MapCspProviderFlags(int flags)
        {
            uint cspFlags = 0;

            if (IsFlagBitSet((uint)flags, (uint)CspProviderFlags.UseMachineKeyStore))
            {
                cspFlags |= (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET;
            }
            if (IsFlagBitSet((uint)flags, (uint)CspProviderFlags.NoPrompt))
            {
                cspFlags |= (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_SILENT;
            }
            if (IsFlagBitSet((uint)flags, (uint)CspProviderFlags.CreateEphemeralKey))
            {
                cspFlags |= (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT;
            }
            return cspFlags;
        }

        /// <summary>
        /// This method checks if the handle is invalid then it throws error
        /// </summary>
        /// <param name="handle">Accepts handle</param>
        internal static void VerifyValidHandle(SafeHandleZeroOrMinusOneIsInvalid handle)
        {
            if (handle.IsInvalid)
            {
                throw new CryptographicException(SR.Cryptography_OpenInvalidHandle);
            }
        }

        /// <summary>
        ///Method helps get the different key properties
        /// </summary>
        /// <param name="safeKeyHandle">Key handle</param>
        /// <param name="keyParam"> Key property you want to get</param>
        /// <returns>Returns the key property</returns>
        internal static byte[] GetKeyParameter(SafeKeyHandle safeKeyHandle, int keyParam)
        {
            byte[] pb = null;
            int cb = 0;
            VerifyValidHandle(safeKeyHandle); //This will throw if handle is invalid

            switch (keyParam)
            {
                case Constants.CLR_KEYLEN:
                {
                    if (!Interop.Advapi32.CryptGetKeyParam(safeKeyHandle, Interop.Advapi32.CryptGetKeyParamFlags.KP_KEYLEN, null, ref cb, 0))
                    {
                        throw GetErrorCode().ToCryptographicException();
                    }
                    pb = new byte[cb];
                    if (!Interop.Advapi32.CryptGetKeyParam(safeKeyHandle, Interop.Advapi32.CryptGetKeyParamFlags.KP_KEYLEN, pb, ref cb, 0))
                    {
                        throw GetErrorCode().ToCryptographicException();
                    }
                    break;
                }
                case Constants.CLR_PUBLICKEYONLY:
                {
                    pb = new byte[1];
                    pb[0] = safeKeyHandle.PublicOnly ? (byte)1 : (byte)0;
                    break;
                }
                case Constants.CLR_ALGID:
                {
                    // returns the algorithm ID for the key
                    if (!Interop.Advapi32.CryptGetKeyParam(safeKeyHandle, Interop.Advapi32.CryptGetKeyParamFlags.KP_ALGID, null, ref cb, 0))
                    {
                        throw GetErrorCode().ToCryptographicException();
                    }
                    pb = new byte[cb];
                    if (!Interop.Advapi32.CryptGetKeyParam(safeKeyHandle, Interop.Advapi32.CryptGetKeyParamFlags.KP_ALGID, pb, ref cb, 0))
                    {
                        throw GetErrorCode().ToCryptographicException();
                    }
                    break;
                }
                // begin: gost
                case Constants.CLR_CIPHEROID:
                {
                    // returns the KP_CIPHEROID for the key
                    if (!Interop.Advapi32.CryptGetKeyParam(safeKeyHandle, Interop.Advapi32.CryptGetKeyParamFlags.KP_CIPHEROID, null, ref cb, 0))
                    {
                        throw GetErrorCode().ToCryptographicException();
                    }
                    pb = new byte[cb];
                    if (!Interop.Advapi32.CryptGetKeyParam(safeKeyHandle, Interop.Advapi32.CryptGetKeyParamFlags.KP_CIPHEROID, pb, ref cb, 0))
                    {
                        throw GetErrorCode().ToCryptographicException();
                    }
                    break;
                }
                // end: gost
                default:
                {
                    Debug.Assert(false);
                    break;
                }
            }
            return pb;
        }

        /// <summary>
        /// Set a key property which is based on byte[]
        /// </summary>
        /// <param name="safeKeyHandle">Key handle</param>
        /// <param name="keyParam"> Key property you want to set</param>
        /// <param name="value"> Key property value you want to set</param>
        internal static void SetKeyParameter(SafeKeyHandle safeKeyHandle, CryptGetKeyParamQueryType keyParam, byte[] value)
        {
            VerifyValidHandle(safeKeyHandle); //This will throw if handle is invalid

            switch (keyParam)
            {
                case CryptGetKeyParamQueryType.KP_IV:
                    if (!Interop.Advapi32.CryptSetKeyParam(safeKeyHandle, (int)keyParam, value, 0))
                        throw new CryptographicException(SR.CryptSetKeyParam_Failed, Convert.ToString(GetErrorCode()));

                    break;
                default:
                    Debug.Fail("Unknown param in SetKeyParameter");
                    break;
            }
        }

        /// <summary>
        /// Set a key property which is based on byte[]
        /// </summary>
        /// <param name="safeKeyHandle">Key handle</param>
        /// <param name="keyParam"> Key property you want to set</param>
        /// <param name="value"> Key property value you want to set</param>
        internal static void SetKeyParameter(SafeKeyHandle safeKeyHandle, int keyParam, byte[] value)
        {
            VerifyValidHandle(safeKeyHandle); //This will throw if handle is invalid

            if (!Interop.Advapi32.CryptSetKeyParam(safeKeyHandle, keyParam, value, 0))
                throw new CryptographicException(SR.CryptSetKeyParam_Failed, Convert.ToString(GetErrorCode()));
        }

        /// <summary>
        /// Set a key property which is based on int
        /// </summary>
        /// <param name="safeKeyHandle">Key handle</param>
        /// <param name="keyParam"> Key property you want to set</param>
        /// <param name="value"> Key property value you want to set</param>
        internal static void SetKeyParameter(SafeKeyHandle safeKeyHandle, CryptGetKeyParamQueryType keyParam, int value)
        {
            VerifyValidHandle(safeKeyHandle); //This will throw if handle is invalid

            switch (keyParam)
            {
                case CryptGetKeyParamQueryType.KP_MODE:
                case CryptGetKeyParamQueryType.KP_MODE_BITS:
                case CryptGetKeyParamQueryType.KP_EFFECTIVE_KEYLEN:
                    if (!Interop.Advapi32.CryptSetKeyParam(safeKeyHandle, (int)keyParam, ref value, 0))
                        throw new CryptographicException(SR.CryptSetKeyParam_Failed, Convert.ToString(GetErrorCode()));

                    break;
                default:
                    Debug.Fail("Unknown param in SetKeyParameter");
                    break;
            }
        }

        /// <summary>
        /// Set a key property which is based on int
        /// </summary>
        /// <param name="safeKeyHandle">Key handle</param>
        /// <param name="keyParam"> Key property you want to set</param>
        /// <param name="value"> Key property value you want to set</param>
        internal static void SetKeyParameter(SafeKeyHandle safeKeyHandle, int keyParam, int value)
        {
            VerifyValidHandle(safeKeyHandle); //This will throw if handle is invalid

            if (!Interop.Advapi32.CryptSetKeyParam(safeKeyHandle, keyParam, ref value, 0))
                throw new CryptographicException(SR.CryptSetKeyParam_Failed, Convert.ToString(GetErrorCode()));
        }

        /// <summary>
        /// Helper method to save the CSP parameters. 
        /// </summary>
        /// <param name="keyType">CSP algorithm type</param>
        /// <param name="userParameters">CSP Parameters passed by user</param>
        /// <param name="defaultFlags">flags </param>
        /// <param name="randomKeyContainer">identifies if it is random key container</param>
        /// <returns></returns>
        internal static CspParameters SaveCspParameters(
            CspAlgorithmType keyType,
            CspParameters userParameters,
            CspProviderFlags defaultFlags,
            out bool randomKeyContainer)
        {
            CspParameters parameters;
            //begin: gost
            if (userParameters != null && userParameters.ProviderType != (int)keyType)
            {
                switch (keyType)
                {
                    case CspAlgorithmType.Dss:
                        userParameters.ProviderType = DefaultDssProviderType;
                        break;
                    case CspAlgorithmType.Gost2001:
                    case CspAlgorithmType.Gost2012_256:
                    case CspAlgorithmType.Gost2012_512:
                        userParameters.ProviderType = (int)keyType;
                        break;
                    case CspAlgorithmType.Rsa:
                    default:
                        userParameters.ProviderType = DefaultRsaProviderType;
                        break;
                }
            }
            //end: gost

            if (userParameters == null)
            {
                //begin: gost
                switch (keyType)
                {
                    case CspAlgorithmType.Dss:
                        parameters = new CspParameters(DefaultDssProviderType, null, null, defaultFlags);
                        break;
                    case CspAlgorithmType.Gost2001:
                    case CspAlgorithmType.Gost2012_256:
                    case CspAlgorithmType.Gost2012_512:
                        parameters = new CspParameters((int) keyType, null, null, defaultFlags);
                        break;
                    case CspAlgorithmType.Rsa:
                    default:
                        parameters = new CspParameters(DefaultRsaProviderType, null, null, defaultFlags);
                        break;
                }
                //end: gost
            }
            else
            {
                ValidateCspFlags(userParameters.Flags);
                parameters = new CspParameters(userParameters);
            }

            if (parameters.KeyNumber == -1)
            {
                // if gost goes here it ends with KeyNumber.Exchange
                parameters.KeyNumber = keyType == CapiHelper.CspAlgorithmType.Dss
                                           ? (int)KeyNumber.Signature
                                           : (int)KeyNumber.Exchange;
            }
            else if (parameters.KeyNumber == CALG_DSS_SIGN || 
                     parameters.KeyNumber == CALG_RSA_SIGN ||
                     parameters.KeyNumber == GostConstants.CALG_GR3410EL ||
                     parameters.KeyNumber == GostConstants.CALG_GR3410_12_256 ||
                     parameters.KeyNumber == GostConstants.CALG_GR3410_12_256)
            {
                parameters.KeyNumber = (int)KeyNumber.Signature;
            }
            else if (parameters.KeyNumber == CALG_RSA_KEYX ||
                     parameters.KeyNumber == GostConstants.CALG_DH_EL_SF ||
                     parameters.KeyNumber == GostConstants.CALG_DH_EL_SF ||
                     parameters.KeyNumber == GostConstants.CALG_DH_GR3410_12_512_SF)
            {
                parameters.KeyNumber = (int)KeyNumber.Exchange;
            }

            // If no key container was specified and UseDefaultKeyContainer is not used, then use CRYPT_VERIFYCONTEXT
            // to generate an ephemeral key
            randomKeyContainer = IsFlagBitSet((uint)parameters.Flags, (uint)CspProviderFlags.CreateEphemeralKey);

            if (parameters.KeyContainerName == null && !IsFlagBitSet((uint)parameters.Flags,
                (uint)CspProviderFlags.UseDefaultKeyContainer))
            {
                // add: gost
                switch (parameters.ProviderType)
                {
                    case (int)CspAlgorithmType.Gost2001:
                    case (int)CspAlgorithmType.Gost2012_256:
                    case (int)CspAlgorithmType.Gost2012_512:
                    {
                        parameters.KeyContainerName = GetRandomKeyContainer();
                        break;
                    }
                    default:
                    {
                        parameters.Flags |= CspProviderFlags.CreateEphemeralKey;
                        break;
                    }
                }
                // end: gost
                randomKeyContainer = true;
            }

            return parameters;
        }

        /// <summary>
        /// Validates the CSP flags are expected
        /// </summary>
        /// <param name="flags">CSP provider flags</param>
        private static void ValidateCspFlags(CspProviderFlags flags)
        {
            // check that the flags are consistent.
            if (IsFlagBitSet((uint)flags, (uint)CspProviderFlags.UseExistingKey))
            {
                CspProviderFlags keyFlags = (CspProviderFlags.UseNonExportableKey |
                                            CspProviderFlags.UseArchivableKey |
                                            CspProviderFlags.UseUserProtectedKey);
                if ((flags & keyFlags) != CspProviderFlags.NoFlags)
                {
                    throw new ArgumentException(SR.Format(SR.Arg_EnumIllegalVal, Convert.ToString(flags)), nameof(flags));
                }
            }
        }

        /// <summary>
        /// Helper function to get the key pair
        /// </summary>
        internal static SafeKeyHandle GetKeyPairHelper(
            CspAlgorithmType keyType,
            CspParameters parameters,
            int keySize,
            SafeProvHandle safeProvHandle)
        {
            // If the key already exists, use it, else generate a new one
            SafeKeyHandle hKey;
            int hr = CapiHelper.GetUserKey(safeProvHandle, parameters.KeyNumber, out hKey);
            if (hr != S_OK)
            {
                hKey.Dispose();
                if (unchecked(IsFlagBitSet((uint)parameters.Flags, (uint)CspProviderFlags.UseExistingKey) ||
                                                                   (uint)hr != (uint)CryptKeyError.NTE_NO_KEY))
                {
                    throw hr.ToCryptographicException();
                }

                // GenerateKey will check for failures and throw an exception
                CapiHelper.GenerateKey(safeProvHandle, parameters.KeyNumber, (int)parameters.Flags,
                                        (uint)keySize, out hKey);
            }

            // check that this is indeed an RSA/DSS key.
            byte[] algid = CapiHelper.GetKeyParameter(hKey, Constants.CLR_ALGID);

            int dwAlgId = (algid[0] | (algid[1] << 8) | (algid[2] << 16) | (algid[3] << 24));

            if ((keyType == CspAlgorithmType.Rsa && dwAlgId != CALG_RSA_KEYX && dwAlgId != CALG_RSA_SIGN) ||
                (keyType == CspAlgorithmType.Dss && dwAlgId != CALG_DSS_SIGN))
            {
                hKey.Dispose();
                throw new CryptographicException(SR.Format(SR.Cryptography_CSP_WrongKeySpec, Convert.ToString(keyType)));
            }

            return hKey;
        }

        internal static SafeKeyHandle GetKeyPairHelper(
            CspAlgorithmType keyType,
            int keyNumber,
            int dwKeySize,
            SafeProvHandle safeProvHandle)
        {
            SafeProvHandle hProv = null;
            SafeKeyHandle hKey = SafeKeyHandle.InvalidHandle;
            try
            {
                hProv = safeProvHandle;

                int err1 = CapiHelper.GetUserKey(
                    hProv,
                    keyNumber,
                    out hKey);
                if (err1 != 0)
                {
                    throw new CryptographicException(err1);
                }

                byte[] buffer1 = CapiHelper.GetKeyParameter(
                    hKey,
                    Constants.CLR_ALGID);
                int algid = ((buffer1[0] | (buffer1[1] << 8)) |
                    (buffer1[2] << 0x10)) | (buffer1[3] << 0x18);

                // Допускаем только 2001 и 2012 и только подпись или шифрование.
                switch (keyType)
                {
                    case CspAlgorithmType.Gost2001:
                        if ((algid != GostConstants.CALG_DH_EL_SF
                            && algid != GostConstants.CALG_GR3410EL))
                        {
                            throw new CryptographicException(SR.Format(SR.Cryptography_CSP_WrongKeySpec, Convert.ToString(keyType)));
                        }
                        break;
                    case CspAlgorithmType.Gost2012_256:
                        if ((algid != GostConstants.CALG_DH_GR3410_12_256_SF
                            && algid != GostConstants.CALG_GR3410_12_256))
                        {
                            throw new CryptographicException(SR.Format(SR.Cryptography_CSP_WrongKeySpec, Convert.ToString(keyType)));
                        }
                        break;
                    case CspAlgorithmType.Gost2012_512:
                        if ((algid != GostConstants.CALG_DH_GR3410_12_512_SF
                            && algid != GostConstants.CALG_GR3410_12_512))
                        {
                            throw new CryptographicException(SR.Format(SR.Cryptography_CSP_WrongKeySpec, Convert.ToString(keyType)));
                        }
                        break;
                    default:
                        throw new CryptographicException(SR.Format(SR.Cryptography_CSP_WrongKeySpec, Convert.ToString(keyType)));
                }
            }
            catch (Exception)
            {
                if (hProv != null)
                    hProv.Close();
                if (hKey != null)
                    hKey.Close();
                throw;
            }
            safeProvHandle = hProv;
            return hKey;
        }

        // begin: gost
        /// <summary>
        /// Генерация ключа.
        /// </summary>
        /// 
        /// <param name="hProv">Провайдер, для которого создается
        /// ключ.</param>
        /// <param name="algid">ALGID ключа.</param>
        /// <param name="flags">Флаги провайдера.</param>
        /// <param name="keySize">Размер открытого ключа в битах.</param>
        /// <param name="hKey">Полученный ключ.</param>
        /// 
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне.</exception>
        /// 
        /// <intdoc><para>Есть у MS аналогичная функция с тем же прототипом, 
        /// и похожей (CRYPT_KEY_CTX другой) реализацией.</para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static void GenerateKey(SafeProvHandle hProv,
            int algid, CspProviderFlags flags, int keySize,
            out SafeKeyHandle hKey)
        {
            int keyFlags = MapCspKeyFlags((int)flags);
            // Дожно быть так, но очередная ошибка в CSP не дает так сделать.
            // keyFlags |= ((uint)keySize) << 16;
            bool ret = CapiHelper.CryptGenKey(hProv,
                algid, keyFlags, out hKey);
            if (!ret)
                throw new CryptographicException(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Генерация ключа с заданными параметрами при генерации.
        /// </summary>
        /// 
        /// <param name="hProv">Провайдер, для которого создается
        /// ключ.</param>
        /// <param name="calg">ALGID ключа.</param>
        /// <param name="flags">Флаги создания ключа, часть
        /// флагов не совместима с генерецией ключа.</param>
        /// <param name="keySize">Размер открытого ключа в битах.</param>
        /// <param name="digestParamSet">OID хэширования.</param>
        /// <param name="publicKeyParamSet">OID возводителя.</param>
        /// <param name="hKey">Полученный ключ.</param>
        /// 
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне.</exception>
        /// 
        /// <intdoc><para>Аналогичная функция у MS отсутствует.</para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static void GenerateKey(SafeProvHandle hProv,
            int calg, CspProviderFlags flags, int keySize,
            string digestParamSet, string publicKeyParamSet,
            out SafeKeyHandle hKey)
        {
            int keyFlags = MapCspKeyFlags((int)flags) | GostConstants.CRYPT_PREGEN;
            // Дожно быть так, но очередная ошибка в CSP не дает так сделать.
            // keyFlags |= ((uint)keySize) << 16 (GostConstants.CRYPT_PREGEN);

            bool ret = CapiHelper.CryptGenKey(
                hProv, calg, keyFlags, out hKey);
            if (!ret)
                throw new CryptographicException(Marshal.GetLastWin32Error());

            SetKeyParamString(hKey, GostConstants.KP_HASHOID,
                digestParamSet);
            SetKeyParamString(hKey, GostConstants.KP_DHOID,
                publicKeyParamSet);
            CapiHelper.SetKeyParameter(hKey, GostConstants.KP_X, null);
        }

        /// <summary>
        /// Экспорт открытого ключа ГОСТ 34.10 в структуру <see cref="Gost3410CspObject"/>.
        /// </summary>
        /// 
        /// <param name="hKey">Эскпортируемый HANDLE ключа.</param>
        /// <param name="pubKey">Открытый ключ.</param>
        /// <param name="alg">Тип алгоритма</param>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// декодирования массива и ошибках на managed уровне.</exception>
        /// <argnull name="pubKey" />
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static void ExportPublicKey(SafeKeyHandle hKey,
            Gost3410CspObject pubKey, CspAlgorithmType alg)
        {
            if (pubKey == null)
                throw new ArgumentNullException("pubKey");
            byte[] data = ExportKeyBlob(hKey,
                SafeKeyHandle.InvalidHandle, GostConstants.PUBLICKEYBLOB);
            AsnHelper.DecodePublicBlob(pubKey, data, alg);
        }

        /// <summary>
        /// Импорт открытого ключа и создание распределенного секрета.
        /// </summary>
        /// 
        /// <param name="hCSP">HANDLE провайдера, в ктороый происходит 
        /// импорт.</param>
        /// <param name="flags">Флаги импорта.</param>
        /// <param name="cspObject">Импортируемый открытый ключ.</param>
        /// <param name="hImportKey">HANDLE секретного ключа
        /// для распределенного секрета.</param>
        /// <param name="hKey">HANDLE ключа распределенного секрета.</param>
        /// <param name="alg">Тип алгоритма</param>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// кодирования BLOB и ошибках на managed уровне.</exception>
        /// <argnull name="cspObject" />
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static void ImportAndMakeSharedSecret(SafeProvHandle hCSP,
            CspProviderFlags flags, Gost3410CspObject cspObject,
            SafeKeyHandle hImportKey, ref SafeKeyHandle hKey, CspAlgorithmType alg)
        {
            if (cspObject == null)
                throw new ArgumentNullException("cspObject");
            byte[] data = AsnHelper.EncodePublicBlob(cspObject, alg);
            ImportKeyBlob(data, hCSP, flags, hImportKey, out hKey);
        }

        /// <summary>
        /// Импорт сессионного ключа в провайдер на другом ключе.
        /// </summary>
        /// 
        /// <param name="hCSP">Провайдер для импорта.</param>
        /// <param name="flags">Флаги импорта.</param>
        /// <param name="cspObject">Импортируемый ключ.</param>
        /// <param name="hImportKey">Ключ, на котором происходит импорт.</param>
        /// <param name="hKey">Импортированный ключ.</param>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// кодирования BLOB и ошибках на managed уровне.</exception>
        /// <argnull name="cspObject" />
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static void ImportSessionWrappedKey(SafeProvHandle hCSP,
            CspProviderFlags flags, GostWrappedKeyObject cspObject,
            SafeKeyHandle hImportKey, ref SafeKeyHandle hKey)
        {
            if (cspObject == null)
                throw new ArgumentNullException("cspObject");
            byte[] data = AsnHelper.EncodeSimpleBlob(cspObject,
                GostConstants.CALG_G28147);
            ImportKeyBlob(data, hCSP, flags, hImportKey, out hKey);
        }

        /// <summary>
        /// Экспорт сессионного ключа на ключе экспорта в структуру
        /// <see cref="GostWrappedKeyObject"/>
        /// </summary>
        /// 
        /// <param name="hSimmKey">Экспортируемый HANDLE ключа.</param>
        /// <param name="hExpKey">HANDLE ключа, на котором происходит 
        /// экспорт.</param>
        /// <param name="wrappedKey">Результат экспорта.</param>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// декодирования массива и ошибках на managed уровне.</exception>
        /// <argnull name="wrappedKey" />
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static void ExportSessionWrapedKey(SafeKeyHandle hSimmKey,
            SafeKeyHandle hExpKey, GostWrappedKeyObject wrappedKey)
        {
            if (wrappedKey == null)
                throw new ArgumentNullException("wrappedKey");
            byte[] data = ExportKeyBlob(hSimmKey,
                hExpKey, GostConstants.SIMPLEBLOB);
            AsnHelper.DecodeSimpleBlob(wrappedKey, data);
        }

        /// <summary>
        /// Импорт BLOB ключа в провайдер.
        /// </summary>
        /// 
        /// <param name="keyBlob">BLOB</param>
        /// <param name="hProv">HANDLE провайдера.</param>
        /// <param name="flags">Флаги импорта.</param>
        /// <param name="hImportKey">Ключ, на котором происходит импорт.</param>
        /// <param name="hKey">HANDLE импортированного ключа.</param>
        /// 
        /// <returns><see cref="KeyNumber.Exchange"/> или 
        /// <see cref="KeyNumber.Signature"/></returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне.</exception>
        /// 
        /// <intdoc><para>Есть у MS аналогичная функция с похожим прототипом
        /// (добавлен параметр hImportKey) и похожей реализацией.</para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static int ImportKeyBlob(byte[] keyBlob,
            SafeProvHandle hProv, CspProviderFlags flags,
            SafeKeyHandle hImportKey, out SafeKeyHandle hKey)
        {
            int keyFlags = MapCspKeyFlags((int)flags);
            bool ret = CapiHelper.CryptImportKey(hProv, keyBlob,
                keyBlob.Length, hImportKey, keyFlags, out hKey);
            if (!ret)
            {
                var hr = Interop.CPError.GetHRForLastWin32Error();
                throw hr.ToCryptographicException();
            }
            int algid_class = BitConverter.ToInt32(keyBlob, 4) & (7 << 13);
            if (algid_class == (5 << 13))
                return (int)KeyNumber.Exchange;
            return (int)KeyNumber.Signature;
        }

        /// <summary>
        /// Экспорт ключа в байтовый массив.
        /// </summary>
        /// 
        /// <param name="hKey">Экспортируемый ключ.</param>
        /// <param name="hExpKey">Ключ, на котором происходит экспорт или
        /// <see cref="SafeKeyHandle.InvalidHandle"/> для экспорта в чистом
        /// виде.</param>
        /// <param name="blobType">Тип экспортируемого BLOB</param>
        /// 
        /// <param name="isPublicCompress">Предоставление отрытого ключа парой (x,b), 
        /// где байт b равен 2, если координата y чётная и 3 в противном случае.</param>
        /// <returns>BLOB.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне.</exception>
        /// 
        /// <intdoc><para>У MS есть аналогичная функция с другим прототипом
        /// (без ключа для экспорта) на native уровне. Прототип изменен, так
        /// как большинство экспорта поддерживается только на другом ключе.</para></intdoc>
        internal static byte[] ExportKeyBlob(SafeKeyHandle hKey,
            SafeKeyHandle hExpKey, int blobType, bool isPublicCompress = false)
        {
            int dwDataLen = 0;
            int dwFlags = 0;
            if (isPublicCompress)
                dwFlags = GostConstants.CRYPT_PUBLICCOMPRESS;

            bool ret = Interop.Advapi32.CryptExportKey(hKey, hExpKey,
                blobType, dwFlags, null, ref dwDataLen);
            if (!ret)
                throw new CryptographicException(Marshal.GetLastWin32Error());
            byte[] data = new byte[dwDataLen];
            ret = Interop.Advapi32.CryptExportKey(hKey, hExpKey,
                blobType, dwFlags, data, ref dwDataLen);
            if (!ret)
                throw new CryptographicException(Marshal.GetLastWin32Error());
            return data;
        }

        /// <summary>
        /// <c>CryptSetKeyParam( ..., const char* data, .... )</c>
        /// </summary>
        /// 
        /// <param name="hKey">HKEY</param>
        /// <param name="param"><c>KP_</c></param>
        /// <param name="value">Значение для установки.</param>
        /// 
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне.</exception>
        /// 
        /// <intdoc><para>Есть у MS нет аналога.</para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static void SetKeyParamString(SafeKeyHandle hKey, int param,
            string value)
        {
            byte[] value_data = Encoding.GetEncoding(0).GetBytes(value);
            CapiHelper.SetKeyParameter(hKey, param, value_data);
        }

        /// <summary>
        /// <c>CryptGetKeyParam</c> с возвратом результата в виде строки.
        /// </summary>
        /// 
        /// <param name="hKey">HKEY</param>
        /// <param name="param">KP_</param>
        /// 
        /// <returns>Строка.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне и ошибках перекодировки строки в текущей locale.</exception>
        /// 
        /// <intdoc><para>У MS отсутствует аналог.</para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static string GetKeyParameterString(SafeKeyHandle hKey,
            int param)
        {
            byte[] blob = GetKeyParameter(hKey, param);
            return ToLocalSecurityString(blob);
        }

        /// <summary>
        /// CryptGetKeyParam с возвратом результата в виде DWORD.
        /// </summary>
        /// 
        /// <param name="hKey">HKEY</param>
        /// <param name="paramID">KP_</param>
        /// 
        /// <returns>DWORD результата.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне.</exception>
        /// 
        /// <intdoc><para>У MS отсутствует аналог, создана для эффективности
        /// (один вызов Crypt) и перекодирования порядка байтов.</para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static int GetKeyParamDw(SafeKeyHandle hKey,
            int paramID)
        {
            byte[] data = CapiHelper.GetKeyParameter(hKey, paramID);
            if (data.Length != 4)
                throw new CryptographicException(GostConstants.NTE_BAD_DATA);
            return BitConverter.ToInt32(data, 0);
        }

        /// <summary>
        /// <c>CryptSetKeyParam( ..., DWORD value, .... )</c>
        /// </summary>
        /// 
        /// <param name="hKey">HKEY</param>
        /// <param name="param"><c>KP_</c></param>
        /// <param name="dwValue">Значение для установки.</param>
        /// 
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне.</exception>
        /// 
        /// <intdoc><para>Есть у MS аналогичная функция с тем же прототипом,
        /// но native реализацией.</para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static void SetKeyParamDw(SafeKeyHandle hKey, int param,
            int dwValue)
        {
            byte[] data = BitConverter.GetBytes(dwValue);
            CapiHelper.SetKeyParameter(hKey, param, data);
        }

        /// <summary>
        /// <c>SetProvParam( ... )</c>
        /// </summary>
        /// 
        /// <param name="hProv">HANDLE провайдера.</param>
        /// <param name="param"></param>
        /// <param name="keyNumber"><see cref="KeyNumber.Exchange"/> или 
        /// <see cref="KeyNumber.Signature"/></param>
        /// <param name="pbData">Данные</param>
        /// 
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне.</exception>
        /// <exception cref="ArgumentException">Если <paramref name="keyNumber"/>,
        /// ни <see cref="KeyNumber.Exchange"/>, ни 
        /// <see cref="KeyNumber.Signature"/> </exception>
        internal static void SetProviderParameter(
            SafeProvHandle hProv, 
            CryptProvParam param,
            int keyNumber, IntPtr pbData)
        {
            if (param == CryptProvParam.PP_KEYEXCHANGE_PIN
               || param == CryptProvParam.PP_SIGNATURE_PIN)
            {
                if (keyNumber == (int)KeyNumber.Exchange)
                {
                    param = CryptProvParam.PP_KEYEXCHANGE_PIN;
                }
                else if (keyNumber == (int)KeyNumber.Signature)
                {
                    param = CryptProvParam.PP_SIGNATURE_PIN;
                }
                else
                {
                    throw new ArgumentException(
                        SR.Cryptography_CSP_WrongKeySpec);
                }
            }
            bool ret = Interop.Advapi32.CryptSetProvParam(hProv, param, pbData, 0);
            if (!ret)
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }
        }
        // end: gost

        /// <summary>
        /// Wrapper for get last error function
        /// </summary>
        /// <returns>returns the error code</returns>
        internal static int GetErrorCode()
        {
            return Interop.CPError.GetLastWin32Error();
            //return Marshal.GetLastWin32Error();
        }

        /// <summary>
        /// Returns PersistKeyInCsp value
        /// </summary>
        /// <param name="safeProvHandle">Safe Prov Handle. Expects a valid handle</param>
        /// <returns>true if key is persisted otherwise false</returns>
        internal static bool GetPersistKeyInCsp(SafeProvHandle safeProvHandle)
        {
            VerifyValidHandle(safeProvHandle);
            return safeProvHandle.PersistKeyInCsp;
        }

        /// <summary>
        /// Sets the PersistKeyInCsp
        /// </summary>
        /// <param name="safeProvHandle">Safe Prov Handle. Expects a valid handle</param>
        /// <param name="fPersistKeyInCsp">Sets the PersistKeyInCsp value</param>
        internal static void SetPersistKeyInCsp(SafeProvHandle safeProvHandle, bool fPersistKeyInCsp)
        {
            VerifyValidHandle(safeProvHandle);
            safeProvHandle.PersistKeyInCsp = fPersistKeyInCsp;
        }

        //---------------------------------------------------------------------------------------
        //
        // Decrypt a symmetric key using the private key in pKeyContext
        //
        // Arguments:
        //    pKeyContext       - private key used for decrypting pbEncryptedKey
        //    pbEncryptedKey    - [in] encrypted symmetric key
        //    cbEncryptedKey    - size, in bytes, of pbEncryptedKey
        //    fOAEP             - TRUE to use OAEP padding, FALSE to use PKCS #1 type 2 padding
        //    ohRetDecryptedKey - [out] decrypted key
        //
        // Notes:
        //    pbEncryptedKey is byte-reversed from the format that CAPI expects. This is for compatibility with
        //    previous CLR versions and other RSA implementations.
        //
        //    This method is the target of the System.Security.Cryptography.RSACryptoServiceProvider.DecryptKey QCall
        //

        // static
        internal static void DecryptKey(SafeKeyHandle safeKeyHandle, byte[] encryptedData, int encryptedDataLength, bool fOAEP, out byte[] decryptedData)
        {
            VerifyValidHandle(safeKeyHandle);
            Debug.Assert(encryptedData != null, "Encrypted Data is null");
            Debug.Assert(encryptedDataLength >= 0, "Encrypted data length is less than 0");

            byte[] dataTobeDecrypted = new byte[encryptedDataLength];
            Buffer.BlockCopy(encryptedData, 0, dataTobeDecrypted, 0, encryptedDataLength);
            Array.Reverse(dataTobeDecrypted);

            int dwFlags = fOAEP ? (int)Interop.Advapi32.CryptDecryptFlags.CRYPT_OAEP : 0;
            int decryptedDataLength = encryptedDataLength;
            if (!Interop.Advapi32.CryptDecrypt(safeKeyHandle, SafeHashHandle.InvalidHandle, true, dwFlags, dataTobeDecrypted, ref decryptedDataLength))
            {
                int ErrCode = GetErrorCode();
                // If we're using OAEP mode and we received an NTE_BAD_FLAGS error, then OAEP is not supported on
                // this platform (XP+ only).  Throw a generic cryptographic exception if we failed to decrypt OAEP
                // padded data in order to prevent a chosen ciphertext attack.  We will allow NTE_BAD_KEY out, since
                // that error does not relate to the padding.  Otherwise just throw a cryptographic exception based on
                // the error code.
                if ((uint)((uint)dwFlags & (uint)Interop.Advapi32.CryptDecryptFlags.CRYPT_OAEP) == (uint)Interop.Advapi32.CryptDecryptFlags.CRYPT_OAEP &&
                                                      unchecked((uint)ErrCode) != (uint)CryptKeyError.NTE_BAD_KEY)
                {
                    if (unchecked((uint)ErrCode) == (uint)CryptKeyError.NTE_BAD_FLAGS)
                    {
                        throw new CryptographicException("Cryptography_OAEP_XPPlus_Only");
                    }
                    else
                    {
                        throw new CryptographicException("Cryptography_OAEPDecoding");
                    }
                }
                else
                {
                    throw ErrCode.ToCryptographicException();
                }
            }


            decryptedData = new byte[decryptedDataLength];
            Buffer.BlockCopy(dataTobeDecrypted, 0, decryptedData, 0, decryptedDataLength);
            return;
        }

        /// <summary>
        /// Get certificate from container
        /// </summary>
        internal static byte[] GetContainerCertificate(
            SafeKeyHandle safeKeyHandle)
        {
            int dwDataLen = 0;
            bool ret = Interop.Advapi32.CryptGetKeyParam(safeKeyHandle,
                Interop.Advapi32.CryptGetKeyParamFlags.KP_CERTIFICATE, null, ref dwDataLen, 0);
            if (!ret)
            {
                int err = GetErrorCode();
                if (err == GostConstants.SCARD_E_NO_SUCH_CERTIFICATE)
                    return null;
                throw new CryptographicException(err);
            }
            byte[] data = new byte[dwDataLen];
            ret = Interop.Advapi32.CryptGetKeyParam(safeKeyHandle,
                Interop.Advapi32.CryptGetKeyParamFlags.KP_CERTIFICATE, data, ref dwDataLen, 0);
            if (!ret)
                throw new CryptographicException(GetErrorCode());
            return data;
        }


        //---------------------------------------------------------------------------------------
        //
        // Encrypt a symmetric key using the public key in pKeyContext
        //
        // Arguments:
        //    safeKeyHandle       [in] Key handle
        //    pbKey             - [in] symmetric key to encrypt
        //    cbKey             - size, in bytes, of pbKey
        //    fOAEP             - TRUE to use OAEP padding, FALSE to use PKCS #1 type 2 padding
        //    ohRetEncryptedKey - [out] byte array holding the encrypted key
        //
        // Notes:
        //    The returned value in ohRetEncryptedKey is byte-reversed from the version CAPI gives us.  This is for
        //    compatibility with previous releases of the CLR and other RSA implementations.
        //
        internal static void EncryptKey(SafeKeyHandle safeKeyHandle, byte[] pbKey, int cbKey, bool foep, ref byte[] pbEncryptedKey)
        {
            VerifyValidHandle(safeKeyHandle);
            Debug.Assert(pbKey != null, "pbKey is null");
            Debug.Assert(cbKey >= 0, $"cbKey is less than 0 ({cbKey})");

            int dwEncryptFlags = foep ? (int)Interop.Advapi32.CryptDecryptFlags.CRYPT_OAEP : 0;
            // Figure out how big the encrypted key will be
            int cbEncryptedKey = cbKey;
            if (!Interop.Advapi32.CryptEncrypt(safeKeyHandle, SafeHashHandle.InvalidHandle, true, dwEncryptFlags, null, ref cbEncryptedKey, cbEncryptedKey))
            {
                throw GetErrorCode().ToCryptographicException();
            }
            // pbData is an in/out buffer for CryptEncrypt. allocate space for the encrypted key, and copy the
            // plaintext key into that space.  Since encrypted keys will have padding applied, the size of the encrypted
            // key should always be larger than the plaintext key, so use that to determine the buffer size.
            Debug.Assert(cbEncryptedKey >= cbKey);
            pbEncryptedKey = new byte[cbEncryptedKey];
            Buffer.BlockCopy(pbKey, 0, pbEncryptedKey, 0, cbKey);

            // Encrypt for real - the last parameter is the total size of the in/out buffer, while the second to last
            // parameter specifies the size of the plaintext to encrypt.
            if (!Interop.Advapi32.CryptEncrypt(safeKeyHandle, SafeHashHandle.InvalidHandle, true, dwEncryptFlags, pbEncryptedKey, ref cbKey, cbEncryptedKey))
            {
                throw GetErrorCode().ToCryptographicException();
            }

            Debug.Assert(cbKey == cbEncryptedKey);
            Array.Reverse(pbEncryptedKey);
        }

        internal static int EncryptData(
            SafeKeyHandle hKey,
            byte[] input,
            int inputOffset,
            int inputCount,
            byte[] output,
            int outputOffset,
            int outputCount,
            bool isFinal)
        {
            VerifyValidHandle(hKey);
            Debug.Assert(input != null);
            Debug.Assert(inputOffset >= 0);
            Debug.Assert(inputCount >= 0);
            Debug.Assert(inputCount <= input.Length - inputOffset);
            Debug.Assert(output != null);
            Debug.Assert(outputOffset >= 0);
            Debug.Assert(outputCount >= 0);
            Debug.Assert(outputCount <= output.Length - outputOffset);
            Debug.Assert((inputCount % 8) == 0);

            // Figure out how big the encrypted data will be
            int cbEncryptedData = inputCount;
            if (!Interop.Advapi32.CryptEncrypt(hKey, SafeHashHandle.InvalidHandle, isFinal, 0, null, ref cbEncryptedData, cbEncryptedData))
            {
                throw GetErrorCode().ToCryptographicException();
            }

            // encryptedData is an in/out buffer for CryptEncrypt. Allocate space for the encrypted data, and copy the
            // plaintext data into that space.  Since encrypted data will have padding applied, the size of the encrypted
            // data should always be larger than the plaintext key, so use that to determine the buffer size.
            Debug.Assert(cbEncryptedData >= inputCount);
            var encryptedData = new byte[cbEncryptedData];
            Buffer.BlockCopy(input, inputOffset, encryptedData, 0, inputCount);

            // Encrypt for real - the last parameter is the total size of the in/out buffer, while the second to last
            // parameter specifies the size of the plaintext to encrypt.
            int encryptedDataLength = inputCount;
            if (!Interop.Advapi32.CryptEncrypt(hKey, SafeHashHandle.InvalidHandle, isFinal, 0, encryptedData, ref encryptedDataLength, cbEncryptedData))
            {
                throw GetErrorCode().ToCryptographicException();
            }
            Debug.Assert(encryptedDataLength == cbEncryptedData);

            if (isFinal)
            {
                Debug.Assert(outputCount == inputCount);
            }
            else
            {
                Debug.Assert(outputCount >= encryptedDataLength);
                outputCount = encryptedDataLength;
            }

            // If isFinal, padding was added so ignore it by using outputCount as size
            Buffer.BlockCopy(encryptedData, 0, output, outputOffset, outputCount);

            return outputCount;
        }

        internal static int DecryptData(
            SafeKeyHandle hKey,
            byte[] input,
            int inputOffset,
            int inputCount,
            byte[] output,
            int outputOffset,
            int outputCount)
        {
            VerifyValidHandle(hKey);
            Debug.Assert(input != null);
            Debug.Assert(inputOffset >= 0);
            Debug.Assert(inputCount >= 0);
            Debug.Assert(inputCount <= input.Length - inputOffset);
            Debug.Assert(output != null);
            Debug.Assert(outputOffset >= 0);
            Debug.Assert(outputCount >= 0);
            Debug.Assert(outputCount <= output.Length - outputOffset);
            Debug.Assert((inputCount % 8) == 0);

            byte[] dataTobeDecrypted = new byte[inputCount];
            Buffer.BlockCopy(input, inputOffset, dataTobeDecrypted, 0, inputCount);

            int decryptedDataLength = inputCount;
            // Always call decryption with false (not final); deal with padding manually
            if (!Interop.Advapi32.CryptDecrypt(hKey, SafeHashHandle.InvalidHandle, false, 0, dataTobeDecrypted, ref decryptedDataLength))
            {
                throw GetErrorCode().ToCryptographicException();
            }

            Buffer.BlockCopy(dataTobeDecrypted, 0, output, outputOffset, decryptedDataLength);

            return decryptedDataLength;
        }

        /// <summary>
        /// Helper for Import CSP
        /// </summary>
        internal static void ImportKeyBlob(SafeProvHandle saveProvHandle, CspProviderFlags flags, bool addNoSaltFlag, byte[] keyBlob, out SafeKeyHandle safeKeyHandle)
        {
            // Compat note: This isn't the same check as the one done by the CLR _ImportCspBlob QCall,
            // but this does match the desktop CLR behavior and the only scenarios it
            // affects are cases where a corrupt blob is passed in.
            bool isPublic = keyBlob.Length > 0 && keyBlob[0] == CapiHelper.PUBLICKEYBLOB;

            int dwCapiFlags = MapCspKeyFlags((int)flags);
            if (isPublic)
            {
                dwCapiFlags &= ~(int)(CryptGenKeyFlags.CRYPT_EXPORTABLE);
            }

            if (addNoSaltFlag)
            {
                // For RC2 running in rsabase.dll compatibility mode, make sure 11 bytes of
                // zero salt are generated when using a 40 bit RC2 key.
                dwCapiFlags |= (int)CryptGenKeyFlags.CRYPT_NO_SALT;
            }

            SafeKeyHandle hKey;
            if (!CryptImportKey(saveProvHandle, keyBlob, keyBlob.Length, SafeKeyHandle.InvalidHandle, dwCapiFlags, out hKey))
            {
                int hr = Interop.CPError.GetHRForLastWin32Error();

                hKey.Dispose();

                throw hr.ToCryptographicException();
            }

            hKey.PublicOnly = isPublic;
            safeKeyHandle = hKey;

            return;
        }

        /// <summary>
        /// Helper for Export CSP
        /// </summary>
        internal static byte[] ExportKeyBlob(bool includePrivateParameters, SafeKeyHandle safeKeyHandle)
        {
            VerifyValidHandle(safeKeyHandle);

            byte[] pbRawData = null;
            int cbRawData = 0;
            int dwBlobType = includePrivateParameters ? PRIVATEKEYBLOB : PUBLICKEYBLOB;

            if (!Interop.Advapi32.CryptExportKey(safeKeyHandle, SafeKeyHandle.InvalidHandle, dwBlobType, 0, null, ref cbRawData))
            {
                throw GetErrorCode().ToCryptographicException();
            }
            pbRawData = new byte[cbRawData];

            if (!Interop.Advapi32.CryptExportKey(safeKeyHandle, SafeKeyHandle.InvalidHandle, dwBlobType, 0, pbRawData, ref cbRawData))
            {
                throw GetErrorCode().ToCryptographicException();
            }
            return pbRawData;
        }

        /// <summary>
        /// Helper for signing and verifications that accept a string to specify a hashing algorithm.
        /// </summary>
        public static int NameOrOidToHashAlgId(string nameOrOid, OidGroup oidGroup)
        {
            // Default Algorithm Id is CALG_SHA1
            if (nameOrOid == null)
                return CapiHelper.CALG_SHA1;

            string oidValue = CryptoConfig.MapNameToOID(nameOrOid);
            if (oidValue == null)
                oidValue = nameOrOid; // we were probably passed an OID value directly

            int algId = GetAlgIdFromOid(oidValue, oidGroup);
            if (algId == 0 || algId == -1)
                throw new CryptographicException(SR.Cryptography_InvalidOID);

            return algId;
        }

        /// <summary>
        /// Helper for signing and verifications that accept a string/Type/HashAlgorithm to specify a hashing algorithm.
        /// </summary>
        public static int ObjToHashAlgId(object hashAlg)
        {
            if (hashAlg == null)
                throw new ArgumentNullException(nameof(hashAlg));

            string hashAlgString = hashAlg as string;
            if (hashAlgString != null)
            {
                int algId = NameOrOidToHashAlgId(hashAlgString, OidGroup.HashAlgorithm);
                return algId;
            }
            else if (hashAlg is HashAlgorithm)
            {
                if (hashAlg is MD5)
                    return CapiHelper.CALG_MD5;

                if (hashAlg is SHA1)
                    return CapiHelper.CALG_SHA1;

                if (hashAlg is SHA256)
                    return CapiHelper.CALG_SHA_256;

                if (hashAlg is SHA384)
                    return CapiHelper.CALG_SHA_384;

                if (hashAlg is SHA512)
                    return CapiHelper.CALG_SHA_512;
            }
            else
            {
                Type hashAlgType = hashAlg as Type;
                if ((object)hashAlgType != null)
                {
                    if (typeof(MD5).IsAssignableFrom(hashAlgType))
                        return CapiHelper.CALG_MD5;

                    if (typeof(SHA1).IsAssignableFrom(hashAlgType))
                        return CapiHelper.CALG_SHA1;

                    if (typeof(SHA256).IsAssignableFrom(hashAlgType))
                        return CapiHelper.CALG_SHA_256;

                    if (typeof(SHA384).IsAssignableFrom(hashAlgType))
                        return CapiHelper.CALG_SHA_384;

                    if (typeof(SHA512).IsAssignableFrom(hashAlgType))
                        return CapiHelper.CALG_SHA_512;
                }
            }

            throw new ArgumentException(SR.Argument_InvalidValue, nameof(hashAlg));
        }

        //begin: gost
        /// <summary>
        /// Получение OID алгоритма для переданного объекта хеширования.
        /// </summary>
        /// 
        /// <param name="hashAlg">Объект хеширования: собственно
        /// объект, OID, строка имени...</param>
        /// 
        /// <returns>OID алгоритма хеширования.</returns>
        /// 
        /// <exception cref="ArgumentException">Переданный объект
        /// не объект алгоритма хеширования.</exception>
        /// 
        /// <intdoc><para>Функция полностью аналогична MS.</para></intdoc>
        internal static string ObjToOidValue(object hashAlg)
        {
            if (hashAlg == null)
                throw new ArgumentNullException("hashAlg");
            string s = null;
            string sHashAlg = hashAlg as string;
            if (sHashAlg != null)
            {
                s = CryptoConfig.MapNameToOID(sHashAlg);
                if (s == null)
                    s = sHashAlg;
            }
            else if ((hashAlg is HashAlgorithm))
            {
                s = CryptoConfig.MapNameToOID(hashAlg.GetType().ToString());
            }
            else if ((hashAlg is Type))
            {
                s = CryptoConfig.MapNameToOID(hashAlg.ToString());
            }
            if (s == null)
                throw new ArgumentException(SR.Argument_InvalidValue, nameof(hashAlg));
            return s;
        }

        /// <summary>
        /// Дублирование HANDLE ключа.
        /// </summary>
        /// 
        /// <param name="hKeySrc">Исходный HANDLE ключа.</param>
        /// <param name="safeProvHandle">HANDLE родительского провайдера</param>
        /// 
        /// <returns>HANDLE дубликата.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне.</exception>
        /// 
        /// <intdoc><para>У MS отсутствует аналог.</para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static SafeKeyHandle DuplicateKey(IntPtr hKeySrc, SafeProvHandle safeProvHandle)
        {
            SafeKeyHandle phKeyDest = SafeKeyHandle.InvalidHandle;
            bool ret = Interop.Advapi32.CryptDuplicateKey(hKeySrc,
                null, 0, ref phKeyDest);
            if (!ret)
                throw new CryptographicException(GetErrorCode());

            phKeyDest.SetParent(safeProvHandle);
            return phKeyDest;
        }

        /// <summary>
        /// Перевод в строку из массива байтов ASCIIZ строки в локальной
        /// кодировке.
        /// </summary>
        /// 
        /// <param name="blob">исходный массив.</param>
        /// 
        /// <returns>Строка.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// декодирования исходной строки.</exception>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        private static string ToLocalSecurityString(byte[] blob)
        {
            string ret;
            try
            {
                ret = Encoding.GetEncoding(0).GetString(blob);
                int i = 0;
                for (; i < ret.Length; i++)
                    if (ret[i] == 0)
                        break;
                if (i == ret.Length)
                    throw new CryptographicException(
                        "Cryptography_CSP_InvalidString");
                ret = ret.Substring(0, i);
            }
            catch (DecoderFallbackException ex)
            {
                throw new CryptographicException(
                    "Cryptography_CSP_InvalidString", ex);
            }
            return ret;
        }

        /// <summary>
        /// Установка пароля на контейнер.
        /// </summary>
        /// <param name="safeProvHandle">HANDLE провайдера.</param>
        /// <param name="keyPassword">Пароль в виде SecureString</param>
        /// <param name="keyNumber">номер ключа (signature, exchnage)</param>
        /// <unmanagedperm action="LinkDemand" />
        internal static void SetPin(SafeProvHandle safeProvHandle,
            SecureString keyPassword, int keyNumber)
        {
            IntPtr ptr1 = IntPtr.Zero;
            if (keyPassword != null)
            {
                ptr1 = Marshal.SecureStringToCoTaskMemAnsi(keyPassword);
            }
            try
            {
                CapiHelper.SetProviderParameter(safeProvHandle, CryptProvParam.PP_KEYEXCHANGE_PIN, keyNumber, ptr1);
            }
            finally
            {
                if (ptr1 != IntPtr.Zero)
                {
                    Marshal.ZeroFreeCoTaskMemAnsi(ptr1);
                }
            }
        }

        /// <summary>
        /// Предварительная прогрузка контейнера в память и получение
        /// HANDLE провайдера уровня CP.
        /// </summary>
        /// 
        /// <param name="safeProvHandle">HANDLE провайдера.</param>
        /// 
        /// <returns>HANDLE провайдера уровня CP.</returns>
        /// 
        /// <intdoc><para>Нет аналога на уровне MS.</para></intdoc>
        internal static IntPtr GetHCryptProv(
            SafeProvHandle safeProvHandle)
        {
            int preret = 0;
            CapiHelper.GetProviderParameterWorker(
                safeProvHandle, null, ref preret, CryptProvParam.PP_HCRYPTPROV);
            return new IntPtr(preret);
        }

        /// <summary>
        /// Вывод диалогового окна выбора контейнера и получение 
        /// имени выбранного контейнера
        /// </summary>
        /// 
        /// <param name="fullyQualifiedContainerName">Вернуть полностью
        /// кваллифицированное имя контейнера.</param>
        /// <param name="machine">Использовать локальное хранилище
        /// компьютера (<see langword="true"/>) или пользователя
        /// (<see langword="true"/>).</param>
        /// <param name="parent">HWND родительского окна или IntPtr.Zero,
        /// для выдачи окна без родителя.</param>
        /// <param name="providerId">Идентификатор криптопровайдера</param>
        /// 
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне.</exception>
        /// 
        /// <returns>Строку имени контейнера.</returns>
        /// 
        /// <intdoc><para>Функция не имеет аналога у MS,
        /// это чисто наша функция.</para></intdoc>
        internal static string SelectContainer(
            bool fullyQualifiedContainerName, bool machine, IntPtr parent, int providerId)
        {
            CspParameters acquireParameters = new CspParameters(providerId);
            if (machine)
                acquireParameters.Flags |= CspProviderFlags.UseMachineKeyStore;
            // Не можем использовать статический провайдер,
            // нам нужна установка Parent и нужен флаг machine
            CapiHelper.AcquireCsp(acquireParameters, out SafeProvHandle safeProvHandle);
            using (safeProvHandle)
            {
                if (parent != IntPtr.Zero)
                {
                    CapiHelper.SetProviderParameter(safeProvHandle, CryptProvParam.PP_CLIENT_HWND, 0, parent);
                }
                StringBuilder builder = new StringBuilder(1024 * 2);
                int dwDataLen = 1024;
                int flags = 0;
                if (fullyQualifiedContainerName)
                    flags |= GostConstants.CRYPT_FQCN;

                bool ret = Interop.Advapi32.CryptGetProvParam(
                    safeProvHandle,
                    CryptProvParam.PP_SELECT_CONTAINER, 
                    builder, 
                    ref dwDataLen, 
                    flags);
                if (!ret)
                    throw new CryptographicException(Marshal.GetLastWin32Error());
                return builder.ToString();
            }
        }

        //end: gost

        /// <summary>
        /// Helper for signing and verifications that accept a string/Type/HashAlgorithm to specify a hashing algorithm.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA5351", Justification = "MD5 is used when the user asks for it.")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA5350", Justification = "SHA1 is used when the user asks for it.")]
        internal static HashAlgorithm ObjToHashAlgorithm(object hashAlg)
        {
            int algId = ObjToHashAlgId(hashAlg);
            switch (algId)
            {
                case CapiHelper.CALG_MD5:
                    return MD5.Create();

                case CapiHelper.CALG_SHA1:
                    return SHA1.Create();

                case CapiHelper.CALG_SHA_256:
                    return SHA256.Create();

                case CapiHelper.CALG_SHA_384:
                    return SHA384.Create();

                case CapiHelper.CALG_SHA_512:
                    return SHA512.Create();

                default:
                    throw new ArgumentException(SR.Argument_InvalidValue, nameof(hashAlg));
            }
        }

        /// <summary>
        /// Convert an OID into a CAPI-1 CALG ID.
        /// </summary>
        private static int GetAlgIdFromOid(string oid, OidGroup oidGroup)
        {
            Debug.Assert(oid != null);

            // CAPI does not have ALGID mappings for all of the hash algorithms - see if we know the mapping
            // first to avoid doing an AD lookup on these values
            if (string.Equals(oid, CapiHelper.OID_OIWSEC_SHA256, StringComparison.Ordinal))
            {
                return CapiHelper.CALG_SHA_256;
            }
            else if (string.Equals(oid, CapiHelper.OID_OIWSEC_SHA384, StringComparison.Ordinal))
            {
                return CapiHelper.CALG_SHA_384;
            }
            else if (string.Equals(oid, CapiHelper.OID_OIWSEC_SHA512, StringComparison.Ordinal))
            {
                return CapiHelper.CALG_SHA_512;
            }
            else
            {
                return global::Interop.Crypt32.FindOidInfo(CryptOidInfoKeyType.CRYPT_OID_INFO_OID_KEY, oid, oidGroup, fallBackToAllGroups: false).AlgId;
            }
        }

        /// <summary>
        /// Helper for RSACryptoServiceProvider.SignData/SignHash apis.
        /// </summary>
        public static byte[] SignValue(SafeProvHandle hProv, SafeKeyHandle hKey, int keyNumber, int calgKey, int calgHash, byte[] hash)
        {
            using (SafeHashHandle hHash = hProv.CreateHashHandle(hash, calgHash))
            {
                int cbSignature = 0;
                if (!Interop.Advapi32.CryptSignHash(hHash, (Interop.Advapi32.KeySpec)keyNumber, null, Interop.Advapi32.CryptSignAndVerifyHashFlags.None, null, ref cbSignature))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw hr.ToCryptographicException();
                }

                byte[] signature = new byte[cbSignature];
                if (!Interop.Advapi32.CryptSignHash(hHash, (Interop.Advapi32.KeySpec)keyNumber, null, Interop.Advapi32.CryptSignAndVerifyHashFlags.None, signature, ref cbSignature))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw hr.ToCryptographicException();
                }

                switch (calgKey)
                {
                    case CALG_RSA_SIGN:
                        Array.Reverse(signature);
                        break;

                    case CALG_DSS_SIGN:
                        ReverseDsaSignature(signature, cbSignature);
                        break;
                    default:
                        throw new InvalidOperationException();
                }
                return signature;
            }
        }

        /// <summary>
        /// Helper for RSACryptoServiceProvider.VerifyData/VerifyHash apis.
        /// </summary>
        public static bool VerifySign(SafeProvHandle hProv, SafeKeyHandle hKey, int calgKey, int calgHash, byte[] hash, byte[] signature)
        {
            switch (calgKey)
            {
                case CALG_RSA_SIGN:
                    signature = signature.CloneByteArray();
                    Array.Reverse(signature);
                    break;

                case CALG_DSS_SIGN:
                    signature = signature.CloneByteArray();
                    ReverseDsaSignature(signature, signature.Length);
                    break;

                default:
                    throw new InvalidOperationException();
            }

            using (SafeHashHandle hHash = hProv.CreateHashHandle(hash, calgHash))
            {
                bool verified = Interop.Advapi32.CryptVerifySignature(hHash, signature, signature.Length, hKey, null, Interop.Advapi32.CryptSignAndVerifyHashFlags.None);
                return verified;
            }
        }

        /// Helper method used by PasswordDeriveBytes.CryptDeriveKey to invoke CAPI CryptDeriveKey.
        public static void DeriveKey(
            SafeProvHandle hProv,
            int algid,
            int algidHash,
            byte[] password,
            int cbPassword,
            int dwFlags,
            byte[] IV_Out,
            int cbIV_In,
            ref byte[] pbKey)
        {
            VerifyValidHandle(hProv);

            SafeHashHandle hHash = null;
            SafeKeyHandle hKey = null;
            try
            {
                if (!CryptCreateHash(hProv, algidHash, SafeKeyHandle.InvalidHandle, Interop.Advapi32.CryptCreateHashFlags.None, out hHash))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw hr.ToCryptographicException();
                }

                // Hash the password string
                if (!Interop.Advapi32.CryptHashData(hHash, password, cbPassword, 0))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw hr.ToCryptographicException();
                }

                // Create a block cipher session key based on the hash of the password
                if (!CryptDeriveKey(hProv, algid, hHash, dwFlags | (int)CryptGenKeyFlags.CRYPT_EXPORTABLE, out hKey))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw hr.ToCryptographicException();
                }

                // Get the key contents
                byte[] rgbKey = null;
                int cbKey = 0;
                UnloadKey(hProv, hKey, ref rgbKey, ref cbKey);

                // Get the length of the IV
                int cbIV = 0;
                if (!Interop.Advapi32.CryptGetKeyParam(hKey, Interop.Advapi32.CryptGetKeyParamFlags.KP_IV, null, ref cbIV, 0))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw hr.ToCryptographicException();
                }

                // Now allocate space for the IV
                byte[] pbIV = new byte[cbIV];
                if (!Interop.Advapi32.CryptGetKeyParam(hKey, Interop.Advapi32.CryptGetKeyParamFlags.KP_IV, pbIV, ref cbIV, 0))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw hr.ToCryptographicException();
                }

                if (cbIV != cbIV_In)
                {
                    throw new CryptographicException(SR.Cryptography_PasswordDerivedBytes_InvalidIV);
                }

                // Copy the IV
                Buffer.BlockCopy(pbIV, 0, IV_Out, 0, cbIV);

                pbKey = new byte[cbKey];
                Buffer.BlockCopy(rgbKey, 0, pbKey, 0, cbKey);
            }
            finally
            {
                hKey?.Dispose();
                hHash?.Dispose();
            }
        }

        //begin: gost
        //HelperMethod used by HashData
        public static void CryptHashData(SafeHashHandle hHash, byte[] pbData, int dwDataLen, int dwFlags)
        {
            unsafe
            {
                bool ret = Interop.Advapi32.CryptHashData(hHash, pbData,
                    dwDataLen, 0);
                if (!ret)
                    throw new CryptographicException(
                        GetErrorCode());
            }
        }

        // /// <summary>
        // /// Завершение хешифрования и получение значения хеша.
        // /// </summary>
        // /// 
        // /// <param name="hHash">HNALDE хеша.</param>
        // /// 
        // /// <returns>Значение хеша.</returns>
        // /// 
        // /// <exception cref="CryptographicException">При ошибках на native
        // /// уровне.</exception>
        // /// 
        // /// <intdoc><para>Есть аналог у MS с тем же прототипом и похожей
        // /// (CRYPT_HASH_CTX другой) реализацией.</para></intdoc>
        // /// 
        // /// <unmanagedperm action="LinkDemand" />
        //internal static byte[] EndHash(SafeHashHandle hHash)
        //{
        //    int dwDataLen = 0;
        //    int dwHashSize = 0;
        //    bool ret = Interop.CryptGetHashParam(hHash,
        //        CryptHashProperty.HP_HASHVAL, out dwHashSize, ref dwDataLen, 0);
        //    if (!ret)
        //        throw new CryptographicException(GetErrorCode());
        //    byte[] data = new byte[dwDataLen];
        //    ret = Interop.CryptGetHashParam(hHash,
        //        CryptHashProperty.HP_HASHVAL, out data, ref dwDataLen, 0);
        //    if (!ret)
        //        throw new CryptographicException(GetErrorCode());
        //    return data;
        //}

        //end:gost

        // Helper method used by DeriveKey (above) to return the key contents.
        // WARNING: This function side-effects its first argument (hProv)
        private static void UnloadKey(SafeProvHandle hProv, SafeKeyHandle hKey, ref byte[] key_out, ref int cb_out)
        {
            SafeKeyHandle hPubKey = null;
            try
            {
                // Import the public key
                if (!CryptImportKey(hProv, s_RgbPubKey, s_RgbPubKey.Length, SafeKeyHandle.InvalidHandle, 0, out hPubKey))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw hr.ToCryptographicException();
                }

                // Determine length of hKey
                int cbOut = 0;
                if (!Interop.Advapi32.CryptExportKey(hKey, hPubKey, SIMPLEBLOB, 0, null, ref cbOut))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw hr.ToCryptographicException();
                }

                // Export hKey
                byte[] key_full = new byte[cbOut];
                if (!Interop.Advapi32.CryptExportKey(hKey, hPubKey, SIMPLEBLOB, 0, key_full, ref cbOut))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw hr.ToCryptographicException();
                }

                // Get size of the key without the header parts
                int sizeOfBlobHeader = sizeof(byte) + sizeof(byte) + sizeof(ushort) + sizeof(int);
                // The format of BLOBHEADER:
                //  BYTE   bType
                //  BYTE   bVersion
                //  WORD   reserved
                //  ALG_ID aiKeyAlg
                int offsetPastHeader = sizeOfBlobHeader + sizeof(int);
                int i;
                checked
                {
                    i = cbOut - sizeOfBlobHeader - sizeof(int) - 2;
                }
                while (i > 0)
                {
                    if (key_full[i + offsetPastHeader] == 0)
                    {
                        break;
                    }

                    i--;
                }

                // Allocate and initialize the return buffer
                key_out = new byte[i];
                Buffer.BlockCopy(key_full, offsetPastHeader, key_out, 0, i);
                Array.Reverse(key_out);
                cb_out = i;
            }
            finally
            {
                hPubKey?.Dispose();
            }
        }

        /// <summary>
        /// Create a CAPI-1 hash handle that contains the specified bits as its hash value.
        /// </summary>
        private static SafeHashHandle CreateHashHandle(this SafeProvHandle hProv, byte[] hash, int calgHash)
        {
            SafeHashHandle hHash;
            if (!CryptCreateHash(hProv, calgHash, SafeKeyHandle.InvalidHandle, Interop.Advapi32.CryptCreateHashFlags.None, out hHash))
            {
                int hr = Interop.CPError.GetHRForLastWin32Error();

                hHash.Dispose();

                throw hr.ToCryptographicException();
            }

            try
            {
                int dwHashSize = 0;
                int cbHashSize = sizeof(int);
                if (!Interop.Advapi32.CryptGetHashParam(hHash, Interop.Advapi32.CryptHashProperty.HP_HASHSIZE, out dwHashSize, ref cbHashSize, 0))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw hr.ToCryptographicException();
                }
                if (dwHashSize != hash.Length)
                    throw unchecked((int)CryptKeyError.NTE_BAD_HASH).ToCryptographicException();

                if (!Interop.Advapi32.CryptSetHashParam(hHash, Interop.Advapi32.CryptHashProperty.HP_HASHVAL, hash, 0))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw hr.ToCryptographicException();
                }

                SafeHashHandle hHashPermanent = hHash;
                hHash = null;
                return hHashPermanent;
            }
            finally
            {
                if (hHash != null)
                {
                    hHash.Dispose();
                }
            }
        }

        public static CryptographicException GetBadDataException()
        {
            const int NTE_BAD_DATA = unchecked((int)CryptKeyError.NTE_BAD_DATA);
            return NTE_BAD_DATA.ToCryptographicException();
        }

        public static CryptographicException GetEFailException()
        {
            return E_FAIL.ToCryptographicException();
        }

        public static bool CryptGetUserKey(
            SafeProvHandle safeProvHandle,
            int dwKeySpec,
            out SafeKeyHandle safeKeyHandle)
        {
            bool response = Interop.Advapi32.CryptGetUserKey(safeProvHandle, dwKeySpec, out safeKeyHandle);

            safeKeyHandle.SetParent(safeProvHandle);

            return response;
        }

        public static bool CryptGenKey(
            SafeProvHandle safeProvHandle,
            int algId,
            int dwFlags,
            out SafeKeyHandle safeKeyHandle)
        {
            bool response = Interop.Advapi32.CryptGenKey(safeProvHandle, algId, dwFlags, out safeKeyHandle);

            safeKeyHandle.SetParent(safeProvHandle);

            return response;
        }

        public static bool CryptGenRandom(SafeProvHandle safeProvHandle, int dwLen, byte[] buffer)
        {
            return  Interop.Advapi32.CryptGenRandom(safeProvHandle, dwLen, buffer);
        }

        public static bool CryptImportKey(
            SafeProvHandle hProv,
            byte[] pbData,
            int dwDataLen,
            SafeKeyHandle hPubKey,
            int dwFlags,
            out SafeKeyHandle phKey)
        {
            bool response = Interop.Advapi32.CryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, out phKey);

            phKey.SetParent(hProv);

            return response;
        }

        public static bool CryptCreateHash(
            SafeProvHandle hProv,
            int algId,
            SafeKeyHandle hKey,
            Interop.Advapi32.CryptCreateHashFlags dwFlags,
            out SafeHashHandle phHash)
        {
            bool response = Interop.Advapi32.CryptCreateHash(hProv, algId, hKey, dwFlags, out phHash);

            phHash.SetParent(hProv);

            return response;
        }

        public static bool CryptDeriveKey(
            SafeProvHandle hProv,
            int algId,
            SafeHashHandle phHash,
            int dwFlags,
            out SafeKeyHandle phKey)
        {
            bool response = Interop.Advapi32.CryptDeriveKey(hProv, algId, phHash, dwFlags, out phKey);

            phKey.SetParent(hProv);

            return response;
        }
    }//End of class CapiHelper : Wrappers

    /// <summary>
    /// All the Crypto flags are capture in following 
    /// </summary>
    internal static partial class CapiHelper
    {
        internal const int CALG_DES = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 1);
        internal const int CALG_RC2 = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | 2);
        internal const int CALG_MD5 = (ALG_CLASS_HASH | ALG_TYPE_ANY | 3);
        internal const int CALG_SHA1 = (ALG_CLASS_HASH | ALG_TYPE_ANY | 4);
        internal const int CALG_SHA_256 = (ALG_CLASS_HASH | ALG_TYPE_ANY | 12);
        internal const int CALG_SHA_384 = (ALG_CLASS_HASH | ALG_TYPE_ANY | 13);
        internal const int CALG_SHA_512 = (ALG_CLASS_HASH | ALG_TYPE_ANY | 14);

        internal const string OID_OIWSEC_SHA256 = "2.16.840.1.101.3.4.2.1";
        internal const string OID_OIWSEC_SHA384 = "2.16.840.1.101.3.4.2.2";
        internal const string OID_OIWSEC_SHA512 = "2.16.840.1.101.3.4.2.3";

        // MS provider names.
        internal const string MS_DEF_DH_SCHANNEL_PROV = "Microsoft DH Schannel Cryptographic Provider";
        internal const string MS_DEF_DSS_DH_PROV = "Microsoft Base DSS and Diffie-Hellman Cryptographic Provider";
        internal const string MS_DEF_DSS_PROV = "Microsoft Base DSS Cryptographic Provider";
        internal const string MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0";
        internal const string MS_DEF_RSA_SCHANNEL_PROV = "Microsoft RSA Schannel Cryptographic Provider";
        internal const string MS_DEF_RSA_SIG_PROV = "Microsoft RSA Signature Cryptographic Provider";
        internal const string MS_ENH_DSS_DH_PROV = "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider";
        internal const string MS_ENH_RSA_AES_PROV = "Microsoft Enhanced RSA and AES Cryptographic Provider";
        internal const string MS_ENHANCED_PROV = "Microsoft Enhanced Cryptographic Provider v1.0";
        internal const string MS_SCARD_PROV = "Microsoft Base Smart Card Crypto Provider";
        internal const string MS_STRONG_PROV = "Microsoft Strong Cryptographic Provider";

        [Flags]
        internal enum CryptGetProvParamPPImpTypeFlags : int
        {
            CRYPT_IMPL_HARDWARE = 0x1,
            CRYPT_IMPL_SOFTWARE = 0x2,
            CRYPT_IMPL_MIXED = 0x3,
            CRYPT_IMPL_UNKNOWN = 0x4,
            CRYPT_IMPL_REMOVABLE = 0x8
        }
        //All the flags are capture here

        internal enum CryptGetKeyParamQueryType : int
        {
            KP_IV = 1,
            KP_MODE = 4,
            KP_MODE_BITS = 5,
            KP_EFFECTIVE_KEYLEN = 19,
            KP_KEYLEN = 9,  // Length of key in bits
            KP_ALGID = 7 // Key algorithm
        }
        internal enum CryptGenKeyFlags : int
        {
            // dwFlag definitions for CryptGenKey
            CRYPT_EXPORTABLE = 0x00000001,
            CRYPT_USER_PROTECTED = 0x00000002,
            CRYPT_CREATE_SALT = 0x00000004,
            CRYPT_UPDATE_KEY = 0x00000008,
            CRYPT_NO_SALT = 0x00000010,
            CRYPT_PREGEN = 0x00000040,
            CRYPT_RECIPIENT = 0x00000010,
            CRYPT_INITIATOR = 0x00000040,
            CRYPT_ONLINE = 0x00000080,
            CRYPT_SF = 0x00000100,
            CRYPT_CREATE_IV = 0x00000200,
            CRYPT_KEK = 0x00000400,
            CRYPT_DATA_KEY = 0x00000800,
            CRYPT_VOLATILE = 0x00001000,
            CRYPT_SGCKEY = 0x00002000,
            CRYPT_ARCHIVABLE = 0x00004000
        }

        [Flags]
        internal enum CryptCreateHashFlags : int
        {
            None = 0,
        }

        internal enum CryptHashProperty : int
        {
            HP_ALGID = 0x0001,  // Hash algorithm
            HP_HASHVAL = 0x0002,  // Hash value
            HP_HASHSIZE = 0x0004,  // Hash value size
            HP_HMAC_INFO = 0x0005,  // information for creating an HMAC
            HP_TLS1PRF_LABEL = 0x0006,  // label for TLS1 PRF
            HP_TLS1PRF_SEED = 0x0007,  // seed for TLS1 PRF
        }

        internal enum KeySpec : int
        {
            AT_KEYEXCHANGE = 1,
            AT_SIGNATURE = 2,
        }

        internal enum CspAlgorithmType
        {
            Rsa = 0,
            Dss = 1,
            Gost2001 = GostConstants.PROV_GOST_2001_DH,
            Gost2012_256 = GostConstants.PROV_GOST_2012_256,
            Gost2012_512 = GostConstants.PROV_GOST_2012_512
        }

        [Flags]
        internal enum CryptSignAndVerifyHashFlags : int
        {
            None = 0x00000000,
            CRYPT_NOHASHOID = 0x00000001,
            CRYPT_TYPE2_FORMAT = 0x00000002,  // Not supported
            CRYPT_X931_FORMAT = 0x00000004,  // Not supported
        }
    } //End CapiHelper:Flags
} //End Namespace Internal.NativeCrypto
