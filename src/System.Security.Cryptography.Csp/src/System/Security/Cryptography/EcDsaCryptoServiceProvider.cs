using Internal.NativeCrypto;
using System.Diagnostics;
using System.IO;

namespace System.Security.Cryptography
{
    public class EcDsaCryptoServiceProvider : ECDsa, ICspAsymmetricAlgorithm
    {
        private int _keySize;
        private readonly CspParameters _parameters;
        private readonly bool _randomKeyContainer;
        private SafeKeyHandle _safeKeyHandle;
        private SafeProvHandle _safeProvHandle;
        private static volatile CspProviderFlags s_useMachineKeyStore = 0;
        private bool _disposed;

        public HashAlgorithmName HashAlgorithmName { get; set; } = HashAlgorithmName.SHA256;

        public EcDsaCryptoServiceProvider()
            : this(0, new CspParameters(CapiHelper.DefaultEcDsaProviderType,
                                       "Crypto-Pro ECDSA and AES CSP",
                                       null,
                                       s_useMachineKeyStore),
                                       true)
        {
        }

        public EcDsaCryptoServiceProvider(int dwKeySize)
            : this(dwKeySize,
                  new CspParameters(CapiHelper.DefaultEcDsaProviderType,
                  "Crypto-Pro ECDSA and AES CSP",
                  null,
                  s_useMachineKeyStore), false)
        {
        }

        public EcDsaCryptoServiceProvider(int dwKeySize, CspParameters parameters)
            : this(dwKeySize, parameters, false)
        {
        }

        public EcDsaCryptoServiceProvider(CspParameters parameters)
            : this(0, parameters, true)
        {
        }

        private EcDsaCryptoServiceProvider(int keySize, CspParameters parameters, bool useDefaultKeySize)
        {
            if (keySize < 0)
            {
                throw new ArgumentOutOfRangeException("dwKeySize", "ArgumentOutOfRange_NeedNonNegNum");
            }

            _parameters = CapiHelper.SaveCspParameters(
                CapiHelper.CspAlgorithmType.EcDsa,
                parameters,
                s_useMachineKeyStore,
                out _randomKeyContainer);

            _keySize = useDefaultKeySize ? 1024 : keySize;

            // If this is not a random container we generate, create it eagerly
            // in the constructor so we can report any errors now.
            if (!_randomKeyContainer)
            {
                // Force-read the SafeKeyHandle property, which will summon it into existence.
                SafeKeyHandle localHandle = SafeKeyHandle;
                Debug.Assert(localHandle != null);
            }
        }

        private SafeProvHandle SafeProvHandle
        {
            get
            {
                if (_safeProvHandle == null)
                {
                    lock (_parameters)
                    {
                        if (_safeProvHandle == null)
                        {
                            SafeProvHandle hProv = CapiHelper.CreateProvHandle(_parameters, _randomKeyContainer);

                            Debug.Assert(hProv != null);
                            Debug.Assert(!hProv.IsInvalid);
                            Debug.Assert(!hProv.IsClosed);

                            _safeProvHandle = hProv;
                        }
                    }

                    return _safeProvHandle;
                }

                return _safeProvHandle;
            }
            set
            {
                lock (_parameters)
                {
                    SafeProvHandle current = _safeProvHandle;

                    if (ReferenceEquals(value, current))
                    {
                        return;
                    }

                    if (current != null)
                    {
                        SafeKeyHandle keyHandle = _safeKeyHandle;
                        _safeKeyHandle = null;
                        keyHandle?.Dispose();
                        current.Dispose();
                    }

                    _safeProvHandle = value;
                }
            }
        }

        private SafeKeyHandle SafeKeyHandle
        {
            get
            {
                if (_safeKeyHandle == null)
                {
                    lock (_parameters)
                    {
                        if (_safeKeyHandle == null)
                        {
                            SafeKeyHandle hKey = CapiHelper.GetKeyPairHelper(
                                CapiHelper.CspAlgorithmType.EcDsa,
                                _parameters,
                                _keySize,
                                SafeProvHandle);

                            Debug.Assert(hKey != null);
                            Debug.Assert(!hKey.IsInvalid);
                            Debug.Assert(!hKey.IsClosed);

                            _safeKeyHandle = hKey;
                        }
                    }
                }

                return _safeKeyHandle;
            }

            set
            {
                lock (_parameters)
                {
                    SafeKeyHandle current = _safeKeyHandle;

                    if (ReferenceEquals(value, current))
                    {
                        return;
                    }

                    _safeKeyHandle = value;
                    current?.Dispose();
                }
            }
        }

        /// <summary>
        /// CspKeyContainerInfo property
        /// </summary>
        public CspKeyContainerInfo CspKeyContainerInfo
        {
            get
            {
                // Desktop compat: Read the SafeKeyHandle property to force the key to load,
                // because it might throw here.
                SafeKeyHandle localHandle = SafeKeyHandle;
                Debug.Assert(localHandle != null);

                return new CspKeyContainerInfo(_parameters, _randomKeyContainer);
            }
        }

        /// <summary>
        /// _keySize property
        /// </summary>
        public override int KeySize
        {
            get
            {
                byte[] keySize = CapiHelper.GetKeyParameter(SafeKeyHandle, Constants.CLR_KEYLEN);
                _keySize = (keySize[0] | (keySize[1] << 8) | (keySize[2] << 16) | (keySize[3] << 24));

                // perform magic to get user expected key size
                // _keySize returs number of bits for storing 2 key components rounded up to a byte
                // but we need to return true bit size for supported sizes
                return (_keySize /(2*8)) switch
                {
                    (256 + 7) / 8 => 256,
                    (384 + 7) / 8 => 384,
                    (521 + 7) / 8 => 521,
                    _ => throw new NotImplementedException()
                };                
            }
        }

        public override KeySizes[] LegalKeySizes
        {
            get
            {
                return new[] { new KeySizes(256, 384, 128), new KeySizes(521, 521, 0) };
            }
        }

        /// <summary>
        /// get set Persisted key in CSP
        /// </summary>
        public bool PersistKeyInCsp
        {
            get
            {
                return CapiHelper.GetPersistKeyInCsp(SafeProvHandle);
            }
            set
            {
                bool oldPersistKeyInCsp = this.PersistKeyInCsp;
                if (value == oldPersistKeyInCsp)
                {
                    return; // Do nothing
                }
                CapiHelper.SetPersistKeyInCsp(SafeProvHandle, value);
            }
        }

        /// <summary>
        /// Gets the information of key if it is a public key
        /// </summary>
        public bool PublicOnly
        {
            get
            {
                byte[] publicKey = CapiHelper.GetKeyParameter(SafeKeyHandle, Constants.CLR_PUBLICKEYONLY);
                return (publicKey[0] == 1);
            }
        }

        /// <summary>
        /// MachineKey store properties
        /// </summary>
        public static bool UseMachineKeyStore
        {
            get
            {
                return (s_useMachineKeyStore == CspProviderFlags.UseMachineKeyStore);
            }
            set
            {
                s_useMachineKeyStore = (value ? CspProviderFlags.UseMachineKeyStore : 0);
            }
        }

        /// <summary>
        /// Dispose the key handles
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_safeKeyHandle != null && !_safeKeyHandle.IsClosed)
                {
                    _safeKeyHandle.Dispose();
                }

                if (_safeProvHandle != null && !_safeProvHandle.IsClosed)
                {
                    _safeProvHandle.Dispose();
                }

                _disposed = true;
            }
        }

        /// <summary>
        ///Exports a blob containing the key information associated with an EcDsaCryptoServiceProvider object.
        /// </summary>
        public byte[] ExportCspBlob(bool includePrivateParameters)
        {
            return CapiHelper.ExportKeyBlob(includePrivateParameters, SafeKeyHandle);
        }

        /// <summary>
        /// This method helps Acquire the default CSP and avoids the need for static SafeProvHandle
        /// in CapiHelper class
        /// </summary>
        private SafeProvHandle AcquireSafeProviderHandle()
        {
            SafeProvHandle safeProvHandle;
            CapiHelper.AcquireCsp(new CspParameters(CapiHelper.DefaultEcDsaProviderType), out safeProvHandle);
            return safeProvHandle;
        }

        /// <summary>
        /// Imports a blob that represents EcDsa key information
        /// </summary>
        /// <param name="keyBlob"></param>
        public void ImportCspBlob(byte[] keyBlob)
        {
            throw new NotImplementedException();
            //ThrowIfDisposed();
            //SafeKeyHandle safeKeyHandle;

            //if (IsPublic(keyBlob))
            //{
            //    SafeProvHandle safeProvHandleTemp = AcquireSafeProviderHandle();
            //    CapiHelper.ImportKeyBlob(safeProvHandleTemp, (CspProviderFlags)0, false, keyBlob, out safeKeyHandle);

            //    // The property set will take care of releasing any already-existing resources.
            //    SafeProvHandle = safeProvHandleTemp;
            //}
            //else
            //{
            //    CapiHelper.ImportKeyBlob(SafeProvHandle, _parameters.Flags, false, keyBlob, out safeKeyHandle);
            //}

            //// The property set will take care of releasing any already-existing resources.
            //SafeKeyHandle = safeKeyHandle;
        }

        // begin: gost
        /// <summary>
        /// Импорт открытого ключа из структуры CERT_PUBLIC_KEY_INFO
        /// </summary>
        /// <param name="publicKeyInfo"></param>
        public void ImportCertificatePublicKey(byte[] publicKeyInfo)
        {
            SafeKeyHandle safeKeyHandle;
            SafeProvHandle safeProvHandleTemp = AcquireSafeProviderHandle();

            CapiHelper.CryptImportPublicKeyInfo(
                safeProvHandleTemp,
                Interop.Advapi32.CertEncodingType.X509_ASN_ENCODING,
                publicKeyInfo,
                out safeKeyHandle);

            // The property set will take care of releasing any already-existing resources.
            _safeProvHandle = safeProvHandleTemp;

            // The property set will take care of releasing any already-existing resources.
            _safeKeyHandle = safeKeyHandle;

            if (_parameters != null)
            {
                _parameters.KeyNumber = _safeKeyHandle.KeySpec;
            }
        }

        // end: gost

        /// <summary>
        /// Computes the hash value of a subset of the specified byte array using the
        /// specified hash algorithm, and signs the resulting hash value.
        /// </summary>
        /// <param name="buffer">The input data for which to compute the hash</param>
        /// <param name="offset">The offset into the array from which to begin using data</param>
        /// <param name="count">The number of bytes in the array to use as data. </param>
        /// <param name="halg">The hash algorithm to use to create the hash value. </param>
        /// <returns>The EcDsa signature for the specified data.</returns>
        public byte[] SignData(byte[] buffer, int offset, int count, object halg)
        {
            int calgHash = CapiHelper.ObjToHashAlgId(halg);
            HashAlgorithm hash = CapiHelper.ObjToHashAlgorithm(halg);
            byte[] hashVal = hash.ComputeHash(buffer, offset, count);
            return SignHash(hashVal, calgHash);
        }

        /// <summary>
        /// Computes the hash value of a subset of the specified byte array using the
        /// specified hash algorithm, and signs the resulting hash value.
        /// </summary>
        /// <param name="buffer">The input data for which to compute the hash</param>
        /// <param name="halg">The hash algorithm to use to create the hash value. </param>
        /// <returns>The EcDsa signature for the specified data.</returns>
        public byte[] SignData(byte[] buffer, object halg)
        {
            int calgHash = CapiHelper.ObjToHashAlgId(halg);
            HashAlgorithm hash = CapiHelper.ObjToHashAlgorithm(halg);
            byte[] hashVal = hash.ComputeHash(buffer);
            return SignHash(hashVal, calgHash);
        }

        /// <summary>
        /// Computes the hash value of a subset of the specified byte array using the
        /// specified hash algorithm, and signs the resulting hash value.
        /// </summary>
        /// <param name="inputStream">The input data for which to compute the hash</param>
        /// <param name="halg">The hash algorithm to use to create the hash value. </param>
        /// <returns>The EcDsa signature for the specified data.</returns>
        public byte[] SignData(Stream inputStream, object halg)
        {
            int calgHash = CapiHelper.ObjToHashAlgId(halg);
            HashAlgorithm hash = CapiHelper.ObjToHashAlgorithm(halg);
            byte[] hashVal = hash.ComputeHash(inputStream);
            return SignHash(hashVal, calgHash);
        }

        /// <summary>
        /// Computes the hash value of a subset of the specified byte array using the
        /// specified hash algorithm, and signs the resulting hash value.
        /// </summary>
        /// <param name="rgbHash">The input data for which to compute the hash</param>
        /// <param name="str">The hash algorithm to use to create the hash value. </param>
        /// <returns>The EcDsa signature for the specified data.</returns>
        public byte[] SignHash(byte[] rgbHash, string str)
        {
            if (rgbHash == null)
                throw new ArgumentNullException(nameof(rgbHash));
            if (PublicOnly)
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);

            int calgHash = CapiHelper.NameOrOidToHashAlgId(str, OidGroup.HashAlgorithm);

            return SignHash(rgbHash, calgHash);
        }

        /// <summary>
        /// Computes the hash value of a subset of the specified byte array using the
        /// specified hash algorithm, and signs the resulting hash value.
        /// </summary>
        /// <param name="rgbHash">The input data for which to compute the hash</param>
        /// <param name="calgHash">The hash algorithm to use to create the hash value. </param>
        /// <returns>The EcDsa signature for the specified data.</returns>
        private byte[] SignHash(byte[] rgbHash, int calgHash)
        {
            Debug.Assert(rgbHash != null);

            return CapiHelper.SignValue(
                SafeProvHandle,
                SafeKeyHandle,
                _parameters.KeyNumber,
                CapiHelper.CALG_ECDSA,
                calgHash,
                rgbHash);
        }

        /// <summary>
        /// Verifies the signature of a hash value.
        /// </summary>
        public bool VerifyData(byte[] buffer, object halg, byte[] signature)
        {
            int calgHash = CapiHelper.ObjToHashAlgId(halg);
            HashAlgorithm hash = CapiHelper.ObjToHashAlgorithm(halg);
            byte[] hashVal = hash.ComputeHash(buffer);
            return VerifyHash(hashVal, calgHash, signature);
        }

        /// <summary>
        /// Verifies the signature of a hash value.
        /// </summary>
        public bool VerifyHash(byte[] rgbHash, string str, byte[] rgbSignature)
        {
            if (rgbHash == null)
                throw new ArgumentNullException(nameof(rgbHash));
            if (rgbSignature == null)
                throw new ArgumentNullException(nameof(rgbSignature));

            int calgHash = CapiHelper.NameOrOidToHashAlgId(str, OidGroup.HashAlgorithm);
            return VerifyHash(rgbHash, calgHash, rgbSignature);
        }

        /// <summary>
        /// Verifies the signature of a hash value.
        /// </summary>
        private bool VerifyHash(byte[] rgbHash, int calgHash, byte[] rgbSignature)
        {
            return CapiHelper.VerifySign(
                SafeProvHandle,
                SafeKeyHandle,
                CapiHelper.CALG_ECDSA,
                calgHash,
                rgbHash,
                rgbSignature);
        }

        ///// <summary>
        ///// find whether an EcDsa key blob is public.
        ///// </summary>
        //private static bool IsPublic(byte[] keyBlob)
        //{
        //    if (keyBlob == null)
        //    {
        //        throw new ArgumentNullException(nameof(keyBlob));
        //    }
        //    // The CAPI RSA public key representation consists of the following sequence:
        //    //  - BLOBHEADER
        //    //  - RSAPUBKEY

        //    // The first should be PUBLICKEYBLOB and magic should be RSA_PUB_MAGIC "RSA1"
        //    if (keyBlob[0] != CapiHelper.PUBLICKEYBLOB)
        //    {
        //        return false;
        //    }
        //    if (keyBlob[11] != 0x31 || keyBlob[10] != 0x41 || keyBlob[9] != 0x53 || keyBlob[8] != 0x52)
        //    {
        //        return false;
        //    }
        //    return true;
        //}

        public byte[] SignHash(
            byte[] hash,
            HashAlgorithmName hashAlgorithm)
        {
            if (hash == null)
                throw new ArgumentNullException(nameof(hash));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw HashAlgorithmNameNullOrEmpty();

            return SignHash(hash, GetAlgorithmId(hashAlgorithm));
        }

        public bool VerifyHash(
            byte[] hash,
            byte[] signature,
            HashAlgorithmName hashAlgorithm)
        {
            if (hash == null)
                throw new ArgumentNullException(nameof(hash));
            if (signature == null)
                throw new ArgumentNullException(nameof(signature));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw HashAlgorithmNameNullOrEmpty();

            return VerifyHash(hash, GetAlgorithmId(hashAlgorithm), signature);
        }

        private static int GetAlgorithmId(HashAlgorithmName hashAlgorithm)
        {
            switch (hashAlgorithm.Name)
            {
                case "MD5":
                    return CapiHelper.CALG_MD5;
                case "SHA1":
                    return CapiHelper.CALG_SHA1;
                case "SHA256":
                    return CapiHelper.CALG_SHA_256;
                case "SHA384":
                    return CapiHelper.CALG_SHA_384;
                case "SHA512":
                    return CapiHelper.CALG_SHA_512;
                default:
                    throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithm.Name);
            }
        }

        private static Exception HashAlgorithmNameNullOrEmpty()
        {
            return new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, "hashAlgorithm");
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(EcDsaCryptoServiceProvider));
            }
        }

        public override byte[] SignHash(byte[] hash)
        {
            return SignHash(hash, HashAlgorithmName);
        }

        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            return VerifyHash(hash, signature, HashAlgorithmName);
        }
    }
}
