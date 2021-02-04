// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Internal.Cryptography;

namespace Internal.NativeCrypto
{
    internal static partial class CapiHelper
    {
        internal static int EncryptDataCp(SafeProvHandle hProv, SafeKeyHandle hKey, byte[] data,
            int ib, int cb, ref byte[] outputBuffer, int outputOffset,
            PaddingMode paddingMode, bool fDone, bool isStream)
        {
            int dwDataLen = (int)cb; // ebp+0x58
            int bufLength = cb; // ebp+0x34
            if (fDone)
            {
                // Мы не используем в отличии от MS реализации Final
                // поэтому на 8 байт CAPI Padding меньше
                bufLength += 8;
            }
            int remainder = cb & 7; // ebp+0x30
            if (cb < 0)
                throw new ArgumentOutOfRangeException("cb", SR.ArgumentOutOfRange_NeedNonNegNum);
            if (ib < 0)
                throw new ArgumentOutOfRangeException("ib", SR.ArgumentOutOfRange_NeedNonNegNum);
            if (ib > data.Length)
                throw new ArgumentException(SR.Argument_InvalidValue, "ib");
            byte[] tmpBuffer = new byte[bufLength]; // ebp + 0x4c
            Array.Clear(tmpBuffer, 0, bufLength);
            Array.Copy(data, ib, tmpBuffer, 0, cb);
            if (fDone)
            {
                byte fill = (byte)(8 - remainder); // ebp - 0x28;
                switch (paddingMode)
                {
                    case PaddingMode.None: // [data]
                        if (remainder == 0)
                            break;
                        if (isStream)
                            break;
                        throw new CryptographicException(
                            SR.Cryptography_InvalidPaddingMode);
                    case PaddingMode.PKCS7: // [data] [length..length]
                    {
                        int c = cb; // ebp+0x44;
                        dwDataLen += fill;
                        while (c < dwDataLen)
                        {
                            tmpBuffer[c++] = fill;
                        }
                    }
                    break;
                    case PaddingMode.Zeros: // [data] [0..0]
                        if (remainder == 0)
                            break;
                        dwDataLen += fill;
                        break;
                    case PaddingMode.ANSIX923: // [data] [0..0] [length]
                    {
                        int c = cb; // ebp+0x48;
                        dwDataLen += fill;
                        // без while: итак 0.
                        tmpBuffer[dwDataLen - 1] = fill;
                        break;
                    }
                    case PaddingMode.ISO10126: // [data] [random] [length]
                    {
                        byte[] tmpBuf = new byte[fill - 1];
                        if (hProv == null || hProv.IsInvalid)
                        {
                            CspParameters gostParameters = new CspParameters(GostConstants.PROV_GOST_2001_DH);
                            using (var rng = new GostRngCryptoServiceProvider(gostParameters))
                            {
                                rng.GetBytes(tmpBuf);
                            }
                        }
                        else
                        {
                            using (var rng = new GostRngCryptoServiceProvider(hProv))
                            {
                                rng.GetBytes(tmpBuf);
                            }
                        }
                        tmpBuf.CopyTo(tmpBuffer, cb);
                        dwDataLen += fill;
                        tmpBuffer[dwDataLen - 1] = fill;
                        break;
                    }
                    default:
                        throw new ArgumentException(
                            SR.Cryptography_InvalidPaddingMode
                            );
                }
            }
            // Утверждалось, что "Это похоже ошибка CSP. Не дает шифровать 0 байт в конце."
            // if (dwDataLen != 0)
            // 
            // Не используем CAPI Padding!
            bool ret = Interop.Advapi32.CryptEncrypt(hKey, SafeHashHandle.InvalidHandle,
                false, 0, tmpBuffer,
                ref dwDataLen, (int)bufLength);
            if (!ret)
                throw new CryptographicException(Interop.CPError.GetLastWin32Error());
            if (outputBuffer == null)
            {
                outputBuffer = new byte[dwDataLen];
                Array.Copy(tmpBuffer, 0, outputBuffer, 0, dwDataLen);
            }
            else
            {
                if (outputOffset < 0)
                    throw new ArgumentOutOfRangeException("outputOffset", SR.ArgumentOutOfRange_NeedNonNegNum);
                if (outputBuffer.Length < dwDataLen)
                    throw new ArgumentException(SR.Argument_InvalidValue);
                if (outputBuffer.Length - dwDataLen < outputOffset)
                    throw new ArgumentException(SR.Argument_InvalidValue);
                Array.Copy(tmpBuffer, 0, outputBuffer, outputOffset, dwDataLen);
            }
            return (int)dwDataLen;
        }

        internal static int DecryptDataCp(SafeKeyHandle hKey,
            byte[] data, int ib, int cb, ref byte[] outputBuffer,
            int outputOffset, PaddingMode PaddingMode, bool fDone)
        {
            int dwDataLen = (int)cb; // ebp+0x5C
            if (ib < 0)
                throw new ArgumentOutOfRangeException("ib", SR.ArgumentOutOfRange_NeedNonNegNum);
            if (cb < 0)
                throw new ArgumentOutOfRangeException("cb", SR.ArgumentOutOfRange_NeedNonNegNum);
            if ((ib > data.Length) || (ib + cb > data.Length))
                throw new ArgumentException(SR.Argument_InvalidValue);
            // CryptDecrypt использует один буфер с данными,
            // поэтому от new не избавиться.
            byte[] tmpBuffer = new byte[dwDataLen]; // ebp + 0x50
            Array.Copy(data, ib, tmpBuffer, 0, dwDataLen);
            if (!Interop.Advapi32.CryptDecrypt(
                hKey, SafeHashHandle.InvalidHandle,
                false, 0, tmpBuffer, ref dwDataLen))
            {
                throw new CryptographicException(Interop.CPError.GetLastWin32Error());
            }
            int realLength = (int)dwDataLen; // ebp + 0x34
            if (fDone)
            {
                byte fill = 0;
                if (PaddingMode == PaddingMode.PKCS7
                    // [data] [length..length]
                    || PaddingMode == PaddingMode.ANSIX923
                    // [data] [0..0] [length]
                    || PaddingMode == PaddingMode.ISO10126
                    // [data] [random] [length]
                    )
                {
                    if (dwDataLen < 8)
                        throw new CryptographicException(GostConstants.NTE_BAD_DATA);
                    fill = tmpBuffer[dwDataLen - 1]; // ebp + 0x4C
                    if (fill > 8)
                        throw new CryptographicException(GostConstants.NTE_BAD_DATA);
                    if (PaddingMode == PaddingMode.PKCS7)
                    {
                        for (int i = dwDataLen - fill; i < dwDataLen - 1; i++)
                        {
                            if (tmpBuffer[i] != fill)
                                throw new CryptographicException(GostConstants.NTE_BAD_DATA);
                        }
                    }
                    else if (PaddingMode == PaddingMode.ANSIX923)
                    {
                        for (int i = dwDataLen - fill; i < dwDataLen - 1; i++)
                        {
                            if (tmpBuffer[i] != 0)
                                throw new CryptographicException(GostConstants.NTE_BAD_DATA);
                        }
                    }
                }
                else if (PaddingMode != PaddingMode.None // [data]
                    && PaddingMode != PaddingMode.Zeros) // [data] [0..0]
                {
                    throw new ArgumentException(SR.Cryptography_InvalidPaddingMode);
                }
                realLength -= fill;
            }
            if (outputBuffer == null)
            {
                outputBuffer = new byte[realLength];
                Array.Copy(tmpBuffer, 0, outputBuffer, 0, realLength);
            }
            else
            {
                if (outputOffset < 0)
                    throw new ArgumentOutOfRangeException("outputOffset", SR.ArgumentOutOfRange_NeedNonNegNum);
                if ((outputBuffer.Length < realLength)
                    || (outputBuffer.Length - realLength < outputOffset))
                    throw new ArgumentException(SR.Argument_InvalidValue);
                Array.Copy(tmpBuffer, 0, outputBuffer, outputOffset, realLength);
            }
            return realLength;
        }

        /// <summary>
        /// Завершение начатого процесса шифрования/расшифрования и
        /// перевод его в начальное состояние.
        /// </summary>
        /// 
        /// <param name="safeKeyHandle">Ключ, на котором происходит 
        /// процесс шифрования расшифрования.</param>
        /// <param name="encrypting">Режим: Зашифрование, расшифрование.</param>
        /// 
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне.</exception>
        internal static void EndCrypt(SafeKeyHandle safeKeyHandle, bool encrypting)
        {
            bool ret;
            int pdwDataLen = 0;
            if (encrypting)
            {
                byte[] tmpBuffer = new byte[32];
                ret = Interop.Advapi32.CryptEncrypt(
                    safeKeyHandle,
                    SafeHashHandle.InvalidHandle,
                    true,
                    0,
                    tmpBuffer,
                    ref pdwDataLen,
                    32);
            }
            else
            {
                ret = Interop.Advapi32.CryptDecrypt(
                    safeKeyHandle,
                    SafeHashHandle.InvalidHandle,
                    true,
                    0,
                    new byte[] { },
                    ref pdwDataLen);
            }

            if (!ret)
                throw new CryptographicException(Interop.CPError.GetLastWin32Error());
        }

        internal static int GenerateRandomBytes(SafeProvHandle provHandle, byte[] buffer)
        {
            int hr = S_OK;
            VerifyValidHandle(provHandle);
            if (!CryptGenRandom(provHandle, buffer.Length, buffer))
            {
                hr = GetErrorCode();
            }
            if (hr != S_OK)
            {
                throw GetErrorCode().ToCryptographicException();
            }
            return buffer.Length;
        }        

        /// <summary>
        /// Generates random keyContainer name
        /// </summary>
        private static string GetRandomKeyContainer()
        {
            return "CLR{" + Guid.NewGuid().ToString().ToUpper() + "}";
        }
    }
}
