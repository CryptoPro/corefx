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
        /// ��������� ����������������
        /// </summary>
        private CspParameters _parameters;

        /// <summary>
        /// ��������� HANDLE ����������
        /// </summary>
        private SafeProvHandle SafeProvHandle
        {
            get
            {
                if (_safeProvHandle.IsInvalid)
                {
                    CapiHelper.AcquireCsp(_parameters, out SafeProvHandle hProv);

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
                if (_safeKeyHandle.IsInvalid)
                    GenerateKey();
                return _safeKeyHandle;
            }
        }

        /// <summary>
        /// ��������� �������� HANDLE ���������� ��� AddRef.
        /// </summary>
        ///
        /// <unmanagedperm action="LinkDemand" />
        internal SafeProvHandle InternalProvHandle
        {
            get
            {
                // ��������� ������ ����.
                if (_safeKeyHandle.IsInvalid)
                    GenerateKey();
                return _safeProvHandle;
            }
        }

        /// <summary>
        /// ��������� ����������
        /// </summary>
        public string CipherOid
        {
            // ���� ���� �� ��� ������ � ������� ��������� - �������� ��� ��������� � SafeKeyHandle
            get
            {
                return CapiHelper.GetKeyParameterString(SafeKeyHandle, Constants.CLR_CIPHEROID);
            }
            set
            {
                CapiHelper.SetKeyParamString(SafeKeyHandle, GostConstants.KP_CIPHEROID, value);
            }
        }

        public Gost28147CryptoServiceProvider()
        {
            Mode = CipherMode.CFB;
            Padding = PaddingMode.None;
            _safeKeyHandle = SafeKeyHandle.InvalidHandle;
            _safeProvHandle = SafeProvHandle.InvalidHandle;

            _parameters = new CspParameters(GostConstants.PROV_GOST_2001_DH);
        }

        public Gost28147CryptoServiceProvider(CspParameters parameters)
        {
            Mode = CipherMode.CFB;
            Padding = PaddingMode.None;
            _safeKeyHandle = SafeKeyHandle.InvalidHandle;
            _safeProvHandle = SafeProvHandle.InvalidHandle;

            _parameters = new CspParameters(parameters.ProviderType);
        }

        /// <summary>
        /// �������� ������� ������������� ���������� �� HANDLE �����.
        /// </summary>
        ///
        /// <remarks><para>��� �������� ������� ������������� ����������
        /// ��������� ����� ��������������� � ���� �������� �� ���������:</para>
        ///
        /// <table>
        /// <tr><th>��������</th><th>��������</th></tr>
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.IV"/></td>
        /// <td><see langword="null"/></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.Mode"/></td>
        /// <td><see cref="System.Security.Cryptography.CipherMode.CFB"/></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.Padding"/></td>
        /// <td><see cref="System.Security.Cryptography.PaddingMode.None"/></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.KeySize"/></td>
        /// <td><c>256</c></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.FeedbackSize"/></td>
        /// <td><c>64</c></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.BlockSize"/></td>
        /// <td><c>64</c></td></tr>
        ///
        /// </table>
        ///
        /// <para>����� ���������� ���������� ����� ����� � ���������
        /// HANDLE ��� �������� ������, HANDLE ���������� �� �����������,
        /// �� ������������� ������� ��� ������������� (DangerousAddRef).
        /// </para>
        /// </remarks>
        ///
        /// <param name="keyHandle">HANDLE ������������� �����.</param>
        /// <param name="providerHandle">HANDLE ����������.</param>
        ///
        /// <argnull name="keyHandle" />
        /// <exception cref="ArgumentException">�������� <c>keyHandle</c>
        /// �������� ���� �� ��������� ���� 28147.
        /// </exception>
        ///
        /// <unmanagedperm action="Demand" />
        public Gost28147CryptoServiceProvider(IntPtr keyHandle, IntPtr providerHandle)
            : this()
        {
            _safeProvHandle = new SafeProvHandle(providerHandle, true);
            _safeKeyHandle = CapiHelper.DuplicateKey(
                keyHandle,
                _safeProvHandle);
            int algid = CapiHelper.GetKeyParamDw(_safeKeyHandle, Constants.CLR_ALGID);
            if (algid != GostConstants.CALG_G28147)
                throw new ArgumentException("algid");
        }

        /// <summary>
        /// �������� ������� ������������� ���������� �� HANDLE �����.
        /// </summary>
        ///
        /// <remarks><para>��� �������� ������� ������������� ����������
        /// ��������� ����� ��������������� � ���� �������� �� ���������:</para>
        ///
        /// <table>
        /// <tr><th>��������</th><th>��������</th></tr>
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.IV"/></td>
        /// <td><see langword="null"/></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.Mode"/></td>
        /// <td><see cref="System.Security.Cryptography.CipherMode.CFB"/></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.Padding"/></td>
        /// <td><see cref="System.Security.Cryptography.PaddingMode.None"/></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.KeySize"/></td>
        /// <td><c>256</c></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.FeedbackSize"/></td>
        /// <td><c>64</c></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.BlockSize"/></td>
        /// <td><c>64</c></td></tr>
        ///
        /// </table>
        ///
        /// <para>����� ���������� ���������� ����� ����� � ���������
        /// HANDLE ��� �������� ������, HANDLE ���������� �� �����������,
        /// �� ������������� ������� ��� ������������� (DangerousAddRef).
        /// </para>
        /// </remarks>
        ///
        /// <param name="keyHandle">HANDLE ������������� �����.</param>
        /// <param name="provHandle">HANDLE ����������.</param>
        ///
        /// <argnull name="keyHandle" />
        /// <exception cref="ArgumentException">�������� <c>keyHandle</c>
        /// �������� ���� �� ��������� ���� 28147.
        /// </exception>
        ///
        /// <unmanagedperm action="LinkDemand" />
        internal Gost28147CryptoServiceProvider(SafeKeyHandle keyHandle,
            SafeProvHandle provHandle) : this()
        {
            // ������������ ���������� CSP �����������
            // ��� �������� ecnryptor
            if (keyHandle == null)
                throw new ArgumentNullException("keyHandle");
            // ��������� ������� ���������� ��������������� ���� 28147.
            // � ���� CSP �������?
            //if (!CPUtils.HasAlgorithm(Constants.CALG_G28147, 0))
            //{
            //    throw new CryptographicException(
            //        Resources.Cryptography_CSP_AlgorithmNotAvailable);
            //}
            _safeKeyHandle = CapiHelper.DuplicateKey(
                keyHandle.DangerousGetHandle(),
                provHandle);

            bool succeded = false;
            provHandle.DangerousAddRef(ref succeded);
            _safeProvHandle = provHandle;

            int algid = CapiHelper.GetKeyParamDw(_safeKeyHandle, Constants.CLR_ALGID);
            if (algid != GostConstants.CALG_G28147)
                throw new ArgumentException("keyHandle");
            // KeySizeValue ��������������� � ������� ������.
            // FeedbackSizeValue ��������������� � ������� ������.
            // BlockSizeValue ��������������� � ������� ������.
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
            return CreateTransform(true);
        }

        public override ICryptoTransform CreateDecryptor()
        {
            return CreateTransform(false);
        }

        public override void GenerateIV()
        {
            using (var rng = new GostRngCryptoServiceProvider())
            {
                IVValue = new byte[IVSize / BitsPerByte];
                rng.GetBytes(IVValue);
            }
        }

        public override void GenerateKey()
        {
            CapiHelper.GenerateKey(SafeProvHandle,
                GostConstants.CALG_G28147, CspProviderFlags.NoFlags,
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
            SafeKeyHandle hSimmKey = ((Gost28147CryptoServiceProvider)prov).SafeKeyHandle;
            int calg = GostConstants.CALG_SIMPLE_EXPORT;
            if (method == GostKeyWrapMethod.CryptoProKeyWrap)
                calg = GostConstants.CALG_PRO_EXPORT;
            else if (method == GostKeyWrapMethod.CryptoPro12KeyWrap)
                calg = GostConstants.CALG_PRO12_EXPORT;
            else if (method != GostKeyWrapMethod.GostKeyWrap)
                throw new ArgumentOutOfRangeException("method");
            byte[] ret = null;
            // ��������� ��������� algid GOST12147
            using (SafeKeyHandle hExpKey = CapiHelper.DuplicateKey(
                SafeKeyHandle.DangerousGetHandle(),
                SafeProvHandle))
            {
                CapiHelper.SetKeyParameter(hExpKey, GostConstants.KP_ALGID, calg);
                CapiHelper.SetKeyParameter(hExpKey, GostConstants.KP_IV, IV);

                GostWrappedKeyObject wrappedKey = new GostWrappedKeyObject();
                CapiHelper.ExportSessionWrapedKey(hSimmKey,
                    hExpKey, wrappedKey);

                ret = wrappedKey.GetXmlWrappedKey();
            }
            return ret;
        }

        /// <summary>
        /// ����������� (���������) ��������� ����.
        /// </summary>
        /// <param name="wrapped">������������� ��������� ����.</param>
        /// <param name="method">�������� �������� �����.</param>
        public override SymmetricAlgorithm Unwrap(byte[] wrapped, GostKeyWrapMethod method)
        {
            GostWrappedKeyObject gwk = new GostWrappedKeyObject();
            gwk.SetByXmlWrappedKey(wrapped);
            int calg = GostConstants.CALG_SIMPLE_EXPORT;
            if (method == GostKeyWrapMethod.CryptoProKeyWrap)
                calg = GostConstants.CALG_PRO_EXPORT;
            else if (method == GostKeyWrapMethod.CryptoPro12KeyWrap)
                calg = GostConstants.CALG_PRO12_EXPORT;
            else if (method != GostKeyWrapMethod.GostKeyWrap)
                throw new ArgumentOutOfRangeException("method");
            SymmetricAlgorithm ret = null;
            // ��������� ��������� algid GOST12147
            using (SafeKeyHandle hExpKey = CapiHelper.DuplicateKey(
                SafeKeyHandle.DangerousGetHandle(),
                SafeProvHandle))
            {
                CapiHelper.SetKeyParamDw(hExpKey, GostConstants.KP_ALGID, calg);
                SafeKeyHandle simmKey = SafeKeyHandle.InvalidHandle;
                CapiHelper.AcquireCsp(_parameters, out SafeProvHandle hProv);

                CapiHelper.ImportSessionWrappedKey(
                    hProv, CspProviderFlags.NoFlags,
                    gwk, hExpKey, ref simmKey);
                ret = new Gost28147CryptoServiceProvider(simmKey, hProv);
            }
            return ret;
        }

        private ICryptoTransform CreateTransform(bool encrypting)
        {
            // ��� ��������� � KeyHandle �������� ��������� �����.
            SafeKeyHandle hDupKey = CapiHelper.DuplicateKey(
                SafeKeyHandle.DangerousGetHandle(),
                SafeProvHandle);

            // ��������� ������ �� ���������
            bool success = false;
            SafeProvHandle.DangerousAddRef(ref success);

            // ��� ��������� � IV �������� ��������� �������������.

            return CreateTransformCore(
                SafeProvHandle,
                hDupKey, 
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
            // ���������� �� �������, ��� � ������ ������ ���� ���������� ��������� ����� ���������, �� �� ���� ����

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
                    CspProviderFlags.NoFlags, GostConstants.G28147_KEYLEN * BitsPerByte,
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

        ///// <summary>
        ///// �������� ������� ������������������ ��������������: ���������.
        ///// </summary>
        ///// 
        ///// <param name="mode">����� ����������</param>
        ///// <param name="rgbIV">�������������</param>
        ///// <param name="feedbackSize">������ ����� ����������.</param>
        ///// <param name="encryptMode">����� ������������ ��� 
        ///// �������������</param>
        ///// <param name="hKey">����</param>
        ///// 
        ///// <returns>��������</returns>
        ///// 
        ///// <remarks><para>������� �� �������� �������� �����, 
        ///// �������������, mode, feedbackSize ������������ �������, �� �� ���
        ///// ��������� ���� �������� ������ �������.</para>
        ///// <para>�������� Padding � ������� ����� ������� �� ��������� 
        ///// �������.</para>
        ///// <para>Transform ���������� ���������� ����� �, ����� �������������,
        ///// ������������ ��� �����������.</para>
        ///// </remarks>
        ///// 
        ///// <exception cref="CryptographicException"><c>mode</c> == 
        ///// <see cref="CipherMode"/>.CTS; ��� <see cref="PaddingMode"/> �� 
        ///// ��������������� <c>mode</c>; ��� ������ CFB ��� ����������� 
        ///// �������� <c>feedbackSize</c>; ��� ������������� ����� 
        ///// <c>rgbIV</c> � ��������������� �������.</exception>
        ///// 
        ///// <unmanagedperm action="LinkDemand" />
        //private ICryptoTransform _NewEncryptor(SafeKeyHandle hKey,
        //    CipherMode mode, byte[] rgbIV,
        //    int feedbackSize, CryptoAPITransformMode encryptMode)
        //{
        //    int num1 = 0;
        //    int[] numArray1 = new int[10];
        //    object[] objArray1 = new object[10];

        //    // �� ������������ CTS. ������ ��������� ����������.
        //    if (mode == CipherMode.CTS)
        //        throw new CryptographicException(
        //            Resources.Cryptography_CSP_CTSNotSupported);
        //    // ������������ ������ ���������� ���� Padding - mode
        //    if (mode == CipherMode.OFB || mode == CipherMode.CFB)
        //    {
        //        if (Padding != PaddingMode.None)
        //            throw new CryptographicException(
        //            Resources.Cryptography_InvalidPaddingMode);
        //    }
        //    // ���������� Pading, �� ���� ��� ������������.
        //    numArray1[num1] = Constants.KP_PADDING;
        //    objArray1[num1] = Constants.WINCRYPT_PADDING_ZERO;
        //    num1++;

        //    // ������������ ������ CFB � feedback �� ����.
        //    if ((mode == CipherMode.CFB)
        //        && (feedbackSize != DefFeedbackSize))
        //    {
        //        throw new CryptographicException(
        //            Resources.Cryptography_CSP_CFBSizeNotSupported);
        //    }
        //    // ��� �����, �������.
        //    if (hKey == null)
        //    {
        //        hKey = SafeKeyHandleCP.InvalidHandle;
        //        COMCryptography.GenerateKey(CPUtils.StaticGost2001ProvHandle,
        //            Constants.CALG_G28147,
        //            CspProviderFlags.NoFlags, Constants.G28147_KEYLEN * 8,
        //            ref hKey);
        //    }
        //    // ���� �������� ��� Handle, ������� ����� �� ���������.

        //    // Mode ������ ������, ��� ��� ��� �������� ����� �� Handle
        //    // �� ����� ���� ������.
        //    numArray1[num1] = Constants.KP_MODE;
        //    objArray1[num1] = mode;
        //    num1++;

        //    // ��� ���� mode ����� ECB ��������� �������������. �������������.
        //    if (mode != CipherMode.ECB)
        //    {
        //        // ���� �� ���, �� �������.
        //        if (rgbIV == null)
        //        {
        //            // �� ���������� GenerateIV: ��������� � ���������� 
        //            // IV ����� ����������.
        //            rgbIV = new byte[IVSize / 8];
        //            CPUtils.StaticRandomNumberGenerator.GetBytes(rgbIV);
        //        }
        //        // � ��������� ������������� �� �����.
        //        if (rgbIV.Length < IVSize / 8)
        //        {
        //            throw new CryptographicException(
        //                Resources.Cryptography_InvalidIVSize);
        //        }
        //        numArray1[num1] = Constants.KP_SV;
        //        objArray1[num1] = rgbIV;
        //        num1++;
        //    }
        //    // ����� ��� ���������� ��� CFB ���������� ��� ����������, ��
        //    // ��� ������ ����� 64 � ��� ��������� �� �������������� CSP.
        //    return new CPCryptoAPITransform(num1, numArray1, objArray1, hKey,
        //        base.PaddingValue, mode, base.BlockSizeValue, encryptMode);
        //}
    }    
}
