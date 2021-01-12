// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static partial class HashProviderDispenser
    {
        private sealed class CryptoApiHmacProvider : HashProvider
        {
            private readonly byte[] _key;
            private SafeHashHandle _hHash;
            private SafeProvHandle _hProv;
            private SafeKeyHandle _hKey;
            private readonly int _calgHash;
            private readonly int _providerType;

            public override int HashSizeInBytes { get; }

            internal CryptoApiHmacProvider(int providerType, int calgHash, byte[] key)
            {
                if (key == null)
                    throw new ArgumentNullException("key");
                if (!ValidKeySize(key.Length, calgHash))
                {
                    throw new ArgumentException(
                        SR.Format(
                            SR.Cryptography_InvalidKeySize));
                }
                _key = key.CloneByteArray();
                _calgHash = calgHash;
                _providerType = providerType;
                SetKey();
                int dwHashSize = 0;
                int cbHashSize = sizeof(int);
                if (!Interop.Advapi32.CryptGetHashParam(_hHash, Interop.Advapi32.CryptHashProperty.HP_HASHSIZE, out dwHashSize, ref cbHashSize, 0))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                if (dwHashSize < 0)
                {
                    throw new PlatformNotSupportedException(
                        SR.Format(
                            SR.Cryptography_UnknownHashAlgorithm, providerType, calgHash));
                }
                HashSizeInBytes = dwHashSize;
            }

            public override void AppendHashData(ReadOnlySpan<byte> data)
            {
                bool ret = Interop.Advapi32.CryptHashData(_hHash, data.ToArray(), data.Length, 0);
                if (!ret)
                    throw new CryptographicException(Interop.CPError.GetLastWin32Error());
            }

            public override unsafe byte[] FinalizeHashAndReset()
            {
                var output = new byte[HashSizeInBytes];
                bool success = TryFinalizeHashAndReset(output, out int bytesWritten);
                Debug.Assert(success);
                Debug.Assert(bytesWritten == output.Length);
                return output;
            }

            public override bool TryFinalizeHashAndReset(Span<byte> destination, out int bytesWritten)
            {
                if (destination.Length < HashSizeInBytes)
                {
                    bytesWritten = 0;
                    return false;
                }

                int hashSize = HashSizeInBytes;
                if (!Interop.Advapi32.CryptGetHashParam(_hHash, Interop.Advapi32.CryptHashProperty.HP_HASHVAL, destination, ref hashSize, 0))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                bytesWritten = hashSize;

                //reinitialize
                _hHash.Dispose();
                _hKey.Dispose();
                _hProv.Dispose();
                SetKey();
                return true;
            }

            public override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _hHash?.Dispose();
                    _hKey?.Dispose();
                    _hProv?.Dispose();
                }
            }

            private bool ValidKeySize(int keysize, int calgHash)
            {
                if (calgHash == GostConstants.CALG_GR3411_2012_512_HMAC && keysize != 64)
                {
                    return false;
                } else if (calgHash == GostConstants.CALG_GR3411_2012_256_HMAC && keysize != 32)
                {
                    return false;
                } else if (calgHash == GostConstants.CALG_GR3411_HMAC && keysize != 32)
                {
                    return false;
                }
                return true;
            }

            private void GetCalgsFromHMAC(int hmacAlgorithm, out int keyCalg, out int keyHashCalg)
            {
                switch (hmacAlgorithm) {
                    case GostConstants.CALG_GR3411_2012_256_HMAC:
                    case GostConstants.CALG_GR3411_HMAC:
                        keyHashCalg = GostConstants.CALG_GR3411;
                        keyCalg = GostConstants.CALG_G28147;
                        break;
                    case GostConstants.CALG_GR3411_2012_512_HMAC:
                        keyHashCalg = GostConstants.CALG_GR3411_2012_512;
                        keyCalg = GostConstants.CALG_SYMMETRIC_512;
                        break;
                    case GostConstants.CALG_MD5:
                    case GostConstants.CALG_SHA1:
                    case GostConstants.CALG_SHA256:
                    case GostConstants.CALG_SHA384:
                    case GostConstants.CALG_SHA512:
                        keyCalg = GostConstants.CALG_GENERIC_SECRET;
                        keyHashCalg = GostConstants.CALG_SHA512;
                        break;
                    default:
                        throw new PlatformNotSupportedException(
                        SR.Format(
                            SR.Cryptography_UnknownHashAlgorithm, -1, hmacAlgorithm));
                }
            }

            private void ImportShortKeyToCSP(SafeProvHandle hProv, int keyCalg, int keyHashCalg, out SafeKeyHandle hMacKey)
            {
                SafeHashHandle hTmpHash;
                if (!Interop.Advapi32.CryptCreateHash(hProv, keyHashCalg, SafeKeyHandle.InvalidHandle, Interop.Advapi32.CryptCreateHashFlags.None, out hTmpHash))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                if (!Interop.Advapi32.CryptSetHashParam(hTmpHash, Interop.Advapi32.CryptHashProperty.HP_HASHVAL, _key ,0))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                if (!Interop.Advapi32.CryptDeriveKey(hProv, keyCalg, hTmpHash, _key.Length << 19, out hMacKey))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                hTmpHash.Dispose();
            }

            private void ImportLongKeyToCSP(SafeProvHandle hProv, out SafeKeyHandle hMacKey)
            {
                int expAlgId = GostConstants.CALG_AES_128;
                SafeKeyHandle hExpKey;
                if (!Interop.Advapi32.CryptGenKey(hProv, expAlgId, 0, out hExpKey))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                int encryptedLen = _key.Length;
                if (!Interop.Advapi32.CryptEncrypt(hExpKey, SafeHashHandle.InvalidHandle, true, 0, null, ref encryptedLen, encryptedLen))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }

                var encKey = new byte[encryptedLen];
                _key.CopyTo(encKey, 0);
                encryptedLen = _key.Length;
                if (!Interop.Advapi32.CryptEncrypt(hExpKey, SafeHashHandle.InvalidHandle, true, 0, encKey, ref encryptedLen, encKey.Length))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }

                int capacity = 8 /* sizeof(CAPI.BLOBHEADER) */ + sizeof(uint) /*ALG_ID*/ + encryptedLen;
                MemoryStream keyBlob = new MemoryStream(capacity);
                BinaryWriter bw = new BinaryWriter(keyBlob);

                // PUBLICKEYSTRUC
                bw.Write((byte)GostConstants.SIMPLEBLOB); // pPubKeyStruc->bType = SIMPLEBLOB
                bw.Write((byte)GostConstants.CUR_BLOB_VERSION); // pPubKeyStruc->bVersion = CUR_BLOB_VERSION
                bw.Write((short)0); // pPubKeyStruc->reserved = 0;
                bw.Write((uint)GostConstants.CALG_GENERIC_SECRET); // pPubKeyStruc->aiKeyAlg;

                //SIMPLEBLOB
                bw.Write((uint)expAlgId);
                bw.Write(encKey);
                var simpleBlob = keyBlob.ToArray();

                if (!Interop.Advapi32.CryptImportKey(hProv, simpleBlob, simpleBlob.Length, hExpKey, 0, out hMacKey))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                hExpKey.Dispose();
            }

            private void SetKey()
            {
                SafeProvHandle hProv;
                if (!Interop.Advapi32.CryptAcquireContext(out hProv, null, null, _providerType, (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                int keyHashCalg;
                int keyCalg;
                GetCalgsFromHMAC(_calgHash, out keyCalg, out keyHashCalg);
                SafeKeyHandle hMacKey;

                //if key Length longer than sha512 output, we can't derive key just from hash, so need to use simpleblob. 
                if (_key.Length > 64)
                {
                    ImportLongKeyToCSP(hProv, out hMacKey);
                } else {
                    ImportShortKeyToCSP(hProv, keyCalg, keyHashCalg, out hMacKey);
                }
                
                //Create Hash with imported Key
                SafeHashHandle hMacHash;
                if (keyCalg == GostConstants.CALG_GENERIC_SECRET) {
                    if (!Interop.Advapi32.CryptCreateHash(hProv, GostConstants.CALG_HMAC, hMacKey, Interop.Advapi32.CryptCreateHashFlags.None, out hMacHash))
                    {
                        int hr = Interop.CPError.GetHRForLastWin32Error();
                        throw new CryptographicException(hr);
                    }
                    var hmacInfo = new Interop.Advapi32.HMAC_INFO();
                    hmacInfo.HashAlgid = _calgHash;
                    if (!Interop.Advapi32.CryptSetHashParam(hMacHash, Interop.Advapi32.CryptHashProperty.HP_HMAC_INFO, hmacInfo.ToByteArray(), 0))
                    {
                        int hr = Interop.CPError.GetHRForLastWin32Error();
                        throw new CryptographicException(hr);
                    }
                } else {
                    if (!Interop.Advapi32.CryptCreateHash(hProv, _calgHash, hMacKey, Interop.Advapi32.CryptCreateHashFlags.None, out hMacHash))
                    {
                        int hr = Interop.CPError.GetHRForLastWin32Error();
                        throw new CryptographicException(hr);
                    }
                }
                _hProv = hProv;
                _hKey = hMacKey;
                _hHash = hMacHash;
                _hHash.SetParent(_hProv);
                _hKey.SetParent(_hProv);
            }
        }
    }
}
