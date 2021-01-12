// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static partial class HashProviderDispenser
    {
        private sealed class CryptoApiHashProvider : HashProvider
        {
            private SafeHashHandle _hHash;
            private SafeProvHandle _hProv;
            private int _calgHash;

            public override int HashSizeInBytes { get; }

            internal CryptoApiHashProvider(int providerType, int calgHash)
            {
                SafeProvHandle hProv;
                if (!Interop.Advapi32.CryptAcquireContext(out hProv, null, null, providerType, (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                SafeHashHandle hHash;
                if (!Interop.Advapi32.CryptCreateHash(hProv, calgHash, SafeKeyHandle.InvalidHandle, (int)Interop.Advapi32.CryptCreateHashFlags.None, out hHash))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }

                int dwHashSize = 0;
                int cbHashSize = sizeof(int);
                if (!Interop.Advapi32.CryptGetHashParam(hHash, Interop.Advapi32.CryptHashProperty.HP_HASHSIZE, out dwHashSize, ref cbHashSize, 0))
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
                _calgHash = calgHash;
                _hHash = hHash;
                _hProv = hProv;
                _hHash.SetParent(_hProv);
            }

            public override void AppendHashData(ReadOnlySpan<byte> data)
            {
                bool ret = Interop.Advapi32.CryptHashData(_hHash, data.ToArray(), data.Length, 0);
                if (!ret)
                    throw new CryptographicException(Interop.CPError.GetLastWin32Error());
            }

            public override byte[] FinalizeHashAndReset()
            {
                var hash = new byte[HashSizeInBytes];
                bool success = TryFinalizeHashAndReset(hash, out int bytesWritten);
                Debug.Assert(success);
                Debug.Assert(bytesWritten == hash.Length);
                return hash;
            }

            public override bool TryFinalizeHashAndReset(Span<byte> destination, out int bytesWritten)
            {
                int hashSize = HashSizeInBytes;
                if (!Interop.Advapi32.CryptGetHashParam(_hHash, Interop.Advapi32.CryptHashProperty.HP_HASHVAL, destination, ref hashSize, 0))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                bytesWritten = hashSize;

                //reinitialize
                _hHash.Dispose();
                if (!Interop.Advapi32.CryptCreateHash(_hProv, _calgHash, SafeKeyHandle.InvalidHandle, (int)Interop.Advapi32.CryptCreateHashFlags.None, out _hHash))
                {
                    int hr = Interop.CPError.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                _hHash.SetParent(_hProv);
                return true;
            }

            public override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _hHash?.Dispose();
                    _hProv?.Dispose();
                }
            }
        }
    }
}
