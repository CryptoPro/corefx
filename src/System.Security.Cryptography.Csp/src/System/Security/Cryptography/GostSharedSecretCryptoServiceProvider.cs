using System.Security.Permissions;
using System.Runtime.InteropServices;
using static Internal.NativeCrypto.CapiHelper;
using Internal.NativeCrypto;

namespace System.Security.Cryptography
{
    /// <summary>
    /// ���������� ����� ������������ ����� ���������������.
    /// </summary>
    /// 
    /// <remarks>
    /// ���� ������������ ������������ ��� ����������/������������� 
    /// ��������� ������������ ������.
    /// </remarks>
    /// 
    /// <doc-sample path="Simple\Encrypt" name="gEncryptFileAgree">������ 
    /// ������������� agree �����.</doc-sample>
    /// 
    /// <cspversions />
    public sealed class GostSharedSecretCryptoServiceProvider :
        GostSharedSecretAlgorithm
    {
        /// <summary>
        /// ������� HANDLE ���������� �����.
        /// </summary>
        private SafeKeyHandle _safeKeyHandle;
        /// <summary>
        /// ������� HANDLE ����������, � ������� ��������� ����.
        /// </summary>
        private SafeProvHandle _safeProvHandle;
        /// <summary>
        /// �������� ����.
        /// </summary>
        private Gost3410CspObject _publicObject;

        /// <summary>
        /// ��� ������������� ���������
        /// </summary>
        private CspAlgorithmType _algType;

        internal GostSharedSecretCryptoServiceProvider()
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// �������� ��������������� ������� �� HANDLE ����� � CSP
        /// </summary>
        /// <param name="key">HANDLE ���������� ����� � CSP.</param>
        /// <param name="prov">HANDLE ���������� (CSP), ������ ��������
        /// ���������� ����.</param>
        /// <param name="publicObject">�������� ����.</param>
        /// <param name="algType"></param>
        /// 
        /// <argnull name="key" />
        /// <argnull name="prov" />
        /// <argnull name="publicObject" />
        /// <exception cref="CryptographicException">��� ������� �� native
        /// ������.</exception>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal GostSharedSecretCryptoServiceProvider(SafeKeyHandle key,
        SafeProvHandle prov, Gost3410CspObject publicObject, CspAlgorithmType algType)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            if (prov == null)
                throw new ArgumentNullException("prov");
            if (publicObject == null)
                throw new ArgumentNullException("publicObject");
            // � ����� � ����������� DuplicateKey, ���������� ������� ���
            _safeKeyHandle = key;
            bool isinc = false;
            _safeKeyHandle.DangerousAddRef(ref isinc);
            _safeProvHandle = prov;
            _safeProvHandle.DangerousAddRef(ref isinc);
            _publicObject = publicObject;
            _algType = algType;
        }

        /// <summary>
        /// ������������ (�������) ������������� �����.
        /// </summary>
        /// 
        /// <remarks><para>������ �������������� ����� ������� �� ������ 
        /// ������������; ��� <see cref="GostKeyWrapMethod.GostKeyWrap"/> � 
        /// <see cref="GostKeyWrapMethod.CryptoProKeyWrap"/>
        /// ������ �������������� ����� ������������ �������� 
        /// <see cref="GostWrappedKey.GetXmlWrappedKey"/>.</para>
        /// 
        /// <para>��� ������������ ����� ������������ �������������
        /// �������� <see cref="SymmetricAlgorithm.IV"/></para>
        /// </remarks>
        /// 
        /// <param name="alg">������ ������ <see cref="SymmetricAlgorithm"/>, 
        /// ���������� ������������ ����.</param>
        /// <param name="method">�������� �������� �����.</param>
        /// 
        /// <returns>������������� ������������ ����.</returns>
        /// 
        /// <seealso cref="GostWrappedKey"/>
        /// <seealso cref="GostSharedSecretCryptoServiceProvider.Unwrap"/>
#if SHARPEI_DESTINATION_FW40
        [SecuritySafeCritical]
#endif
        public override byte[] Wrap(SymmetricAlgorithm alg,
            GostKeyWrapMethod method)
        {
            Gost28147 gost = alg as Gost28147;
            if (gost == null)
            {
                throw new ArgumentException(nameof(alg));
            }
            Gost28147CryptoServiceProvider prov = gost as
                Gost28147CryptoServiceProvider;
            if (prov == null)
            {
                using (Gost28147CryptoServiceProvider p =
                    new Gost28147CryptoServiceProvider())
                {
                    return p.Wrap(prov, method);
                }
            }
            return Wrap(prov, method);
        }

        /// <summary>
        /// Wrap ����� Gost28147CryptoServiceProvider �� agree.
        /// </summary>
        /// 
        /// <param name="prov">��������� ����</param>
        /// <param name="method">����� ������������ �����.</param>
        /// 
        /// <returns>������������� ������������ ����</returns>
        private byte[] Wrap(Gost28147CryptoServiceProvider prov,
            GostKeyWrapMethod method)
        {
            if (method == GostKeyWrapMethod.CryptoProKeyWrap)
                return CryptoProWrap(prov);
            else if (method == GostKeyWrapMethod.CryptoPro12KeyWrap)
                return CryptoProWrap(prov, GostConstants.CALG_PRO12_EXPORT);
            else if (method == GostKeyWrapMethod.GostKeyWrap)
                return GostWrap(prov);
            else
                throw new ArgumentOutOfRangeException("method");
        }

        /// <summary>
        /// Wrap ����� Gost28147CryptoServiceProvider �� agree
        /// �� <see cref="GostKeyWrapMethod.CryptoProKeyWrap"/>.
        /// </summary>
        /// 
        /// <param name="prov">��������� ����.</param>
        /// <param name="calgProExport">CALG ��������� �������� ������ ���</param>
        /// <returns>������������� ������������ ����.</returns>
        /// 
        /// <exception cref="CryptographicException">��� �������
        /// �� managed ������.</exception>
        private byte[] CryptoProWrap(Gost28147CryptoServiceProvider prov, int calgProExport = GostConstants.CALG_PRO_EXPORT)
        {
            if (calgProExport != GostConstants.CALG_PRO_EXPORT && calgProExport != GostConstants.CALG_PRO12_EXPORT)
            {
                throw new ArgumentOutOfRangeException("calgProExport");
            }

            SafeKeyHandle hSimmKey = prov.SafeKeyHandle;
            GostWrappedKeyObject wrappedKey = new GostWrappedKeyObject();
            SafeKeyHandle hExpKey = SafeKeyHandle.InvalidHandle;

            try
            {
                CapiHelper.ImportAndMakeSharedSecret(_safeProvHandle,
                    CspProviderFlags.NoFlags, _publicObject, _safeKeyHandle,
                    ref hExpKey, _algType);

                CapiHelper.SetKeyParamDw(hExpKey, GostConstants.KP_ALGID,
                    calgProExport);

                CapiHelper.ExportSessionWrapedKey(hSimmKey,
                    hExpKey, wrappedKey);
            }
            finally
            {
                if (!hExpKey.IsClosed)
                    hExpKey.Close();
            }
            return wrappedKey.GetXmlWrappedKey();
        }


        /// <summary>
        /// Wrap ����� Gost28147CryptoServiceProvider �� agree
        /// �� <see cref="GostKeyWrapMethod.GostKeyWrap"/>.
        /// </summary>
        /// 
        /// <param name="prov">��������� ����.</param>
        /// 
        /// <returns>������������� ������������ ����.</returns>
        /// 
        /// <exception cref="CryptographicException">��� �������
        /// �� managed ������.</exception>
        private byte[] GostWrap(Gost28147CryptoServiceProvider prov)
        {
            SafeKeyHandle hSimmKey = prov.SafeKeyHandle;
            GostWrappedKeyObject wrappedKey = new GostWrappedKeyObject();
            SafeKeyHandle hExpKey = SafeKeyHandle.InvalidHandle;

            try
            {
                CapiHelper.ImportAndMakeSharedSecret(_safeProvHandle,
                    CspProviderFlags.NoFlags, _publicObject, _safeKeyHandle,
                    ref hExpKey, _algType);

                CapiHelper.SetKeyParamDw(hExpKey, GostConstants.KP_ALGID,
                    GostConstants.CALG_SIMPLE_EXPORT);

                CapiHelper.ExportSessionWrapedKey(hSimmKey,
                    hExpKey, wrappedKey);
            }
            finally
            {
                if (!hExpKey.IsClosed)
                    hExpKey.Close();
            }
            return wrappedKey.GetXmlWrappedKey();
        }

        /// <summary>
        /// ������������� ������������� �����.
        /// </summary>
        /// 
        /// <param name="wrapped">������������� ��������� ����.</param>
        /// <param name="method">����� ������������ �����.</param>
        /// 
        /// <returns>������ ������ <see cref="SymmetricAlgorithm"/>, 
        /// ���������� �������������� �������� ����.</returns>
        /// 
        /// <remarks><para>������ �������������� ����� ������� �� ������ 
        /// ������������; ��� <see cref="GostKeyWrapMethod.GostKeyWrap"/> � 
        /// <see cref="GostKeyWrapMethod.CryptoProKeyWrap"/>
        /// ������ �������������� ����� ������������ �������� 
        /// <see cref="GostWrappedKey.GetXmlWrappedKey"/>.</para>
        /// </remarks>
        /// 
        /// <exception cref="CryptographicException">��� �������
        /// �� managed ������.</exception>
#if SHARPEI_DESTINATION_FW40
        [SecuritySafeCritical]
#endif
        public override SymmetricAlgorithm Unwrap(byte[] wrapped,
            GostKeyWrapMethod method)
        {
            GostWrappedKeyObject gwk = new GostWrappedKeyObject();
            gwk.SetByXmlWrappedKey(wrapped);
            if (method == GostKeyWrapMethod.CryptoProKeyWrap)
            {
                return CryptoProUnwrap(wrapped, GostConstants.CALG_PRO_EXPORT);
            }
            else if (method == GostKeyWrapMethod.CryptoPro12KeyWrap)
            {
                // � ������ � ������ 2012 �� �� ������, ��� �� ������� �� ProExport ��� ProExport12
                // ��-�� �������� ������������� (������ ��������� �� ProExport, ������ ������ �� ProExport12). ��������� ��� ���������
                return CryptoProUnwrap(wrapped);
            }
            else if (method == GostKeyWrapMethod.GostKeyWrap)
            {
                return GostUnwrap(wrapped);
            }
            else
            {
                throw new ArgumentOutOfRangeException("method");
            }
        }

        /// <summary>
        /// ������������� ������������� ����� ��
        /// �� <see cref="GostKeyWrapMethod.CryptoProKeyWrap"/>.
        /// </summary>
        /// 
        /// <param name="wrapped">������������� ��������� ����.</param>
        /// <param name="calgProExport">OID ��������� ��������</param>
        /// <returns>������ ������ <see cref="SymmetricAlgorithm"/>, 
        /// ���������� �������������� �������� ����.</returns>
        /// 
        /// <exception cref="CryptographicException">��� �������
        /// �� managed ������.</exception>
        private SymmetricAlgorithm CryptoProUnwrap(byte[] wrapped, int calgProExport)
        {
            if (calgProExport != GostConstants.CALG_PRO_EXPORT && calgProExport != GostConstants.CALG_PRO12_EXPORT)
            {
                throw new ArgumentOutOfRangeException("calgProExport");
            }

            GostWrappedKeyObject gwk = new GostWrappedKeyObject();
            gwk.SetByXmlWrappedKey(wrapped);

            SafeKeyHandle simmKey = SafeKeyHandle.InvalidHandle;
            SafeKeyHandle hExpKey = SafeKeyHandle.InvalidHandle;
            try
            {
                CapiHelper.ImportAndMakeSharedSecret(_safeProvHandle,
                    CspProviderFlags.NoFlags, _publicObject, _safeKeyHandle,
                    ref hExpKey, _algType);

                CapiHelper.SetKeyParamDw(hExpKey, GostConstants.KP_ALGID,
                    calgProExport);

                CapiHelper.ImportSessionWrappedKey(_safeProvHandle,
                    CspProviderFlags.NoFlags, gwk, hExpKey, ref simmKey);
            }
            finally
            {
                if (!hExpKey.IsClosed)
                    hExpKey.Close();
            }

            return new Gost28147CryptoServiceProvider(simmKey, _safeProvHandle);
        }

        /// <summary>
        /// ������������� ������������� ����� ��
        /// �� <see cref="GostKeyWrapMethod.CryptoProKeyWrap"/>.
        /// </summary>
        /// 
        /// <param name="wrapped">������������� ��������� ����.</param>
        /// 
        /// <returns>������ ������ <see cref="SymmetricAlgorithm"/>, 
        /// ���������� �������������� �������� ����.</returns>
        /// 
        /// <exception cref="CryptographicException">��� �������
        /// �� managed ������.</exception>
        private SymmetricAlgorithm CryptoProUnwrap(byte[] wrapped)
        {
            try
            {
                return this.CryptoProUnwrap(wrapped, GostConstants.CALG_PRO12_EXPORT);
            }
            catch (CryptographicException ex)
            {
                if (Marshal.GetHRForException(ex) == -2146893819)
                {
                    // bad data - ������� ������ �� ������ ���������
                    return this.CryptoProUnwrap(wrapped, GostConstants.CALG_PRO_EXPORT);
                }
                else
                {
                    throw;
                }
            }
        }

        /// <summary>
        /// ������������� ������������� ����� ��
        /// �� <see cref="GostKeyWrapMethod.GostKeyWrap"/>.
        /// </summary>
        /// 
        /// <param name="wrapped">������������� ��������� ����.</param>
        /// 
        /// <returns>������ ������ <see cref="SymmetricAlgorithm"/>, 
        /// ���������� �������������� �������� ����.</returns>
        /// 
        /// <exception cref="CryptographicException">��� �������
        /// �� managed ������.</exception>
        private SymmetricAlgorithm GostUnwrap(byte[] wrapped)
        {
            GostWrappedKeyObject gwk = new GostWrappedKeyObject();
            gwk.SetByXmlWrappedKey(wrapped);

            SafeKeyHandle simmKey = SafeKeyHandle.InvalidHandle;
            SafeKeyHandle hExpKey = SafeKeyHandle.InvalidHandle;
            try
            {
                CapiHelper.ImportAndMakeSharedSecret(_safeProvHandle,
                    CspProviderFlags.NoFlags, _publicObject, _safeKeyHandle,
                    ref hExpKey, _algType);

                CapiHelper.SetKeyParamDw(hExpKey, GostConstants.KP_ALGID,
                    GostConstants.CALG_SIMPLE_EXPORT);

                CapiHelper.ImportSessionWrappedKey(_safeProvHandle,
                    CspProviderFlags.NoFlags, gwk, hExpKey, ref simmKey);
            }
            finally
            {
                if (!hExpKey.IsClosed)
                    hExpKey.Close();
            }

            return new Gost28147CryptoServiceProvider(simmKey, _safeProvHandle);
        }

        /// <summary>
        /// ��������� �������� (�� ���������) HANDLE �����.
        /// </summary>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal SafeKeyHandle SafeKeyHandle
        {
            get
            {
                return _safeKeyHandle;
            }
        }

        /// <summary>
        /// ��������� �������� (�� ���������) HANDLE �����.
        /// </summary>
        /// 
        /// <unmanagedperm action="Demand" />
        public IntPtr KeyHandle
        {
            [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
            get
            {
                return SafeKeyHandle.DangerousGetHandle();
            }
        }

        /// <summary>
        /// ��������� �������� HANDLE ���������� ��� ��������� RefCount.
        /// </summary>
        /// 
        /// <unmanagedperm action="Demand" />
        public IntPtr ProviderHandle
        {
            [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
            get
            {
                return InternalProvHandle.DangerousGetHandle();
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
                return _safeProvHandle;
            }
        }

        /// <summary>
        /// �������� HANDLE ����� ���������������� � ���.
        /// </summary>
        /// 
        /// <param name="disposing">����� �� finalize.</param>
        protected override void Dispose(bool disposing)
        {
            if ((_safeKeyHandle != null) && !_safeKeyHandle.IsClosed)
            {
                _safeKeyHandle.DangerousRelease();
            }
            if ((_safeProvHandle != null) && !_safeProvHandle.IsClosed)
            {
                _safeProvHandle.DangerousRelease();
            }
            base.Dispose(disposing);
        }
    }
}
