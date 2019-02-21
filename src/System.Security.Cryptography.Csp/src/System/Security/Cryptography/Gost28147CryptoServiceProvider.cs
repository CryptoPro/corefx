// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.ComponentModel;

namespace System.Security.Cryptography
{
    using System.Diagnostics;
    using Internal.NativeCrypto;

    [EditorBrowsable(EditorBrowsableState.Never)]
    public sealed class Gost28147CryptoServiceProvider : Gost28147
    {
        /// <summary>
        /// ������ ����� 256 ���.
        /// </summary>
        internal const int DefKeySize = 256;
        /// <summary>
        /// ������ ����� 64 ����.
        /// </summary>
        internal const int DefBlockSize = 64;
        /// <summary>
        /// ������ ���������� 64 ����.
        /// </summary>
        internal const int DefFeedbackSize = 64;
        /// <summary>
        /// ������ ������������� 64 ����.
        /// </summary>
        internal const int IVSize = 64;

        private const int BitsPerByte = 8;

        /// <summary>
        /// ����� ����������
        /// </summary>
        private SafeProvHandle _safeProvHandle;

        /// <summary>
        /// ����� �����
        /// </summary>
        private SafeKeyHandle _safeKeyHandle;

        /// <summary>
        /// ��������� HANDLE ����������
        /// </summary>
        private SafeProvHandle SafeProvHandle
        {
            get
            {
                if (_safeProvHandle == null)
                {
                    CapiHelper.AcquireCsp(new CspParameters(GostConstants.PROV_GOST_2001_DH), out SafeProvHandle hProv);

                    Debug.Assert(hProv != null);
                    Debug.Assert(!hProv.IsInvalid);
                    Debug.Assert(!hProv.IsClosed);

                    _safeProvHandle = hProv;

                    return _safeProvHandle;
                }

                return _safeProvHandle;
            }
        }

        /// <summary>
        /// ��������� �������� (�� ���������) HANDLE �����.
        /// </summary>
        ///
        /// <unmanagedperm action="LinkDemand" />
        ///
        /// <remarks><para>
        /// �������� <code>KP_PADDING</code>, <code>KP_MODE</code> � �����������
        /// ��� ������ �� ��������� �
        /// <see cref="System.Security.Cryptography.SymmetricAlgorithm.Padding"/>,
        /// <see cref="System.Security.Cryptography.SymmetricAlgorithm.Mode"/>.
        /// </para></remarks>
        internal SafeKeyHandle SafeKeyHandle
        {
            [SecurityCritical]
            get
            {
                if (_safeKeyHandle == null)
                    GenerateKey();
                return _safeKeyHandle;
            }
        }

        public Gost28147CryptoServiceProvider()
        {
            Mode = CipherMode.CFB;
            Padding = PaddingMode.None;
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            throw new NotImplementedException();
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            throw new NotImplementedException();
        }

        public override ICryptoTransform CreateEncryptor()
        {
            // ��� ��������� � KeyHandle �������� ��������� �����.
            SafeKeyHandle hDupKey = CapiHelper.DuplicateKey(SafeKeyHandle.DangerousGetHandle());
            // ��� ��������� � IV �������� ��������� �������������.
            return CreateTransform(true);
        }

        public override ICryptoTransform CreateDecryptor()
        {
            // ��� ��������� � KeyHandle �������� ��������� �����.
            SafeKeyHandle hDupKey = CapiHelper.DuplicateKey(SafeKeyHandle.DangerousGetHandle());
            // ��� ��������� � IV �������� ��������� �������������.
            return CreateTransform(false);
        }

        public override void GenerateIV()
        {
            using (var rng = new GostRngCryptoServiceProvider(SafeProvHandle))
            {
                IVValue = new byte[IVSize / BitsPerByte];
                rng.GetBytes(IVValue);
            }
        }

        public override void GenerateKey()
        {
            CapiHelper.GenerateKey(SafeProvHandle,
                GostConstants.CALG_G28147, (int)CspProviderFlags.NoFlags,
                GostConstants.G28147_KEYLEN * BitsPerByte, out _safeKeyHandle);
            KeyValue = null;
            KeySizeValue = GostConstants.G28147_KEYLEN * BitsPerByte;
        }

        public override byte[] ComputeHash(HashAlgorithm hash)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// ������������ (�������) ��������� ����.
        /// </summary>
        /// <param name="prov">��������� ����.</param>
        /// <param name="method">�������� �������� �����.</param>
        /// <returns>������������� ������������ ����</returns>
        public override byte[] Wrap(Gost28147 prov, GostKeyWrapMethod method)
        {
            throw new NotImplementedException();
            //SafeKeyHandle hSimmKey = ((Gost28147CryptoServiceProvider)prov).SafeKeyHandle;
            //int calg = GostConstants.CALG_SIMPLE_EXPORT;
            //if (method == GostKeyWrapMethod.CryptoProKeyWrap)
            //    calg = GostConstants.CALG_PRO_EXPORT;
            //else if (method == GostKeyWrapMethod.CryptoPro12KeyWrap)
            //    calg = GostConstants.CALG_PRO12_EXPORT;
            //else if (method != GostKeyWrapMethod.GostKeyWrap)
            //    throw new ArgumentOutOfRangeException("method");
            //byte[] ret = null;
            //// ��������� ��������� algid GOST12147
            //using (SafeKeyHandle hExpKey = CapiHelper.DuplicateKey(SafeKeyHandle.DangerousGetHandle())
            //{
            //    CapiHelper.SetKeyParameter(hExpKey, GostConstants.KP_ALGID, calg);
            //    CapiHelper.SetKeyParameter(hExpKey, GostConstants.KP_IV, IV);

            //    GostWrappedKeyObject wrappedKey = new GostWrappedKeyObject();
            //    CapiHelper.ExportSessionWrapedKey(hSimmKey,
            //        hExpKey, wrappedKey);

            //    ret = wrappedKey.GetXmlWrappedKey();
            //}
            //return ret;
        }

        /// <summary>
        /// ����������� (���������) ��������� ����.
        /// </summary>
        /// <param name="wrapped">������������� ��������� ����.</param>
        /// <param name="method">�������� �������� �����.</param>
        public override SymmetricAlgorithm Unwrap(byte[] wrapped, GostKeyWrapMethod method)
        {
            throw new NotImplementedException();
        }

        private ICryptoTransform CreateTransform(bool encrypting)
        {
            return CreateTransformCore(
                SafeProvHandle,
                SafeKeyHandle, 
                base.ModeValue, 
                base.PaddingValue, 
                IV, 
                base.BlockSizeValue, 
                base.FeedbackSizeValue, 
                encrypting);
        }

        private static ICryptoTransform CreateTransformCore(
            SafeProvHandle hProv,
            SafeKeyHandle hKey,
            CipherMode mode,
            PaddingMode padding,
            byte[] rgbIV,
            int blockSize,
            int feedbackSize, 
            bool encrypting)
        {
            //#Q_ ToDo ������ ���� ���� �� � ����� �������� ��� �������� ���������� � GostCryptoAPITransform
            // ���������� �� �������, ��� � ������ ������ ���� ���������� ���������, �� �� ���� ����

            int num1 = 0;
            int[] numArray1 = new int[10];
            object[] objArray1 = new object[10];

            // �� ������������ CTS. ������ ��������� ����������.
            if (mode == CipherMode.CTS)
                throw new ArgumentException(
                    SR.Argument_InvalidValue, nameof(mode));  //SR.Cryptography_CSP_CTSNotSupported
            // ������������ ������ ���������� ���� Padding - mode
            if (mode == CipherMode.OFB || mode == CipherMode.CFB)
            {
                if (padding != PaddingMode.None)
                    throw new CryptographicException(
                    SR.Cryptography_InvalidPaddingMode);
            }
            // ���������� Pading, �� ���� ��� ������������.
            numArray1[num1] = GostConstants.KP_PADDING;
            objArray1[num1] = GostConstants.WINCRYPT_PADDING_ZERO;
            num1++;

            // ������������ ������ CFB � feedback �� ����.
            if ((mode == CipherMode.CFB)
                && (feedbackSize != DefFeedbackSize))
            {
                throw new ArgumentException(SR.Argument_InvalidValue, nameof(feedbackSize));
            }
            // ��� �����, �������.
            if (hKey == null)
            {
                CapiHelper.GenerateKey(hProv,
                    GostConstants.CALG_G28147,
                    (int)CspProviderFlags.NoFlags, GostConstants.G28147_KEYLEN * BitsPerByte,
                    out hKey);
            }
            // ���� �������� ��� Handle, ������� ����� �� ���������.

            // Mode ������ ������, ��� ��� ��� �������� ����� �� Handle
            // �� ����� ���� ������.
            numArray1[num1] = GostConstants.KP_MODE;
            objArray1[num1] = mode;
            num1++;

            // ��� ���� mode ����� ECB ��������� �������������. �������������.
            if (mode != CipherMode.ECB)
            {
                // ���� �� ���, �� �������.
                if (rgbIV == null)
                {
                    if (!encrypting)
                    {
                        // ��� ������������� IV ������ ���� �����
                        throw new CryptographicException(SR.Cryptography_MissingIV);
                    }
                    // �� ���������� GenerateIV: ��������� � ����������
                    // IV ����� ����������.
                        rgbIV = new byte[IVSize / 8];
                    using (var rng = new GostRngCryptoServiceProvider(hProv))
                    {
                        rng.GetBytes(rgbIV);
                    }
                }
                // ��������� ������������� �� �����.
                if (rgbIV.Length < IVSize / BitsPerByte)
                {
                    throw new CryptographicException(
                        SR.Cryptography_InvalidIVSize);
                }
                numArray1[num1] = GostConstants.KP_SV;
                objArray1[num1] = rgbIV;
                num1++;
            }

            // ����� ��� ���������� ��� CFB ���������� ��� ����������, ��
            // ��� ������ ����� 64 � ��� ��������� �� �������������� CSP.
            return new GostCryptoAPITransform(num1, numArray1, objArray1, hKey, hProv,
                padding, mode, blockSize, encrypting);
        }
    }    
}
