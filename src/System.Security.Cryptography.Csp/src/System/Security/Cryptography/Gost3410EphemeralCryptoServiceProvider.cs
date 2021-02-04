using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Permissions;
using System;
using Internal.NativeCrypto;
using static Internal.NativeCrypto.CapiHelper;
using System.IO;

namespace System.Security.Cryptography
{  
    /// <summary>
    /// �������� ������������ ����� ������ (SharedSecret) �� ������ 
    /// ��������� ���� � 34.10,
    /// ���������� ����� � ����������������.
    /// </summary>
    /// 
    /// <cspversions />
    public sealed class Gost3410EphemeralCryptoServiceProvider : Gost3410
    {
        /// <summary>
        /// HANDLE �����.
        /// </summary>
        private SafeKeyHandle _safeKeyHandle;
        /// <summary>
        /// HANDLE ����������.
        /// </summary>
        private SafeProvHandle _safeProvHandle;

        /// <summary>
        /// ��������� �������� (�� ���������) HANDLE key.
        /// </summary>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal SafeKeyHandle InternalKeyHandle
        {
            get
            {
                return _safeKeyHandle;
            }
        }

        /// <summary>
        /// ��������� �������� (�� ���������) HANDLE key.
        /// </summary>
        /// 
        /// <unmanagedperm action="Demand" />
        public IntPtr KeyHandle
        {
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            get
            {
                return InternalKeyHandle.DangerousGetHandle();
            }
        }

        /// <summary>
        /// ��������� �������� HANDLE ���������� ��� ��������� RefCount.
        /// </summary>
        /// 
        /// <unmanagedperm action="Demand" />
        public IntPtr ProviderHandle
        {
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
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
        /// ������������� ��������� � ��������� �����������. 
        /// </summary>
        /// <param name="basedOn">��������� ���������, �� ������ ��������
        /// ����� ������������ ��������� �������� ����. ������������
        /// OID ����������� � ��������� �����, ��������� ��������� �� 
        /// ������������.</param>
        public Gost3410EphemeralCryptoServiceProvider(Gost3410Parameters basedOn)
        {
            _safeKeyHandle = SafeKeyHandle.InvalidHandle;
            _safeProvHandle = AcquireSafeProviderHandle();

            // ��������� ���������� ����� ��� ����������� �������� ������������.
            // ��������� ����� �� �����.
            CapiHelper.GenerateKey(_safeProvHandle,
                GostConstants.CALG_DH_EL_EPHEM, CspProviderFlags.NoFlags,
                GostConstants.GOST_3410EL_SIZE, basedOn.DigestParamSet,
                basedOn.PublicKeyParamSet, out _safeKeyHandle);
        }

        /// <summary>
        /// ������������� ��������� � ����������� ��������� 
        /// ������ ���������� CSP.
        /// </summary>
        public Gost3410EphemeralCryptoServiceProvider()
        {
            _safeKeyHandle = SafeKeyHandle.InvalidHandle;
            CapiHelper.GenerateKey(_safeProvHandle,
                GostConstants.CALG_DH_EL_EPHEM, (CspProviderFlags)0, 
                GostConstants.GOST_3410EL_SIZE, out _safeKeyHandle);
        }

    /// <summary>
    /// ������� ���������� ���������.
    /// </summary>
    /// 
    /// <param name="includePrivateParameters"><see langword="true"/>, 
    /// ��� �������� ���������� �����.</param>
    /// 
    /// <returns>��������� ���������.</returns>
    /// 
    /// <exception cref="CryptographicException">��� ��������
    /// ���������� �����.</exception>
    /// 
    /// <remarks>
    /// <if notdefined="userexp"><para>�� ������������ ������������ 
    /// � ������ ������ ��� �������� 
    /// ���������� ����� ������ ���������� ���������� 
    /// <see cref="CryptographicException"/>.</para></if>
    /// </remarks>
    public override Gost3410Parameters ExportParameters(
        bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new CryptographicException(SR.Argument_InvalidValue, "includePrivateParameters equal true ");
        }
        Gost3410CspObject obj1 = new Gost3410CspObject();
        CapiHelper.ExportPublicKey(_safeKeyHandle, obj1, CspAlgorithmType.Gost2001);
        return obj1.Parameters;
    }

    /// <summary>
    /// ������ ���������� ���������.
    /// </summary>
    /// 
    /// <param name="parameters">��������� ���������.</param>
    /// 
    /// <exception cref="CryptographicException">������.
    /// </exception>
    public override void ImportParameters(Gost3410Parameters parameters)
    {
        // ������ ��������� ����� - ��� �������� agree, 
        // ������������� ���������� �� ��������������.
        // ����� ����� ������������� ������ ������ private
        throw new NotSupportedException();
    }

        /// <summary>
        /// �������� ����� ������������.
        /// </summary>
        /// 
        /// <param name="alg">��������� ��������� �����.</param>
        /// 
        /// <returns>�������������� ������.</returns>
        /// 
        /// <intdoc>�� ��������� ����������� SharedSecret,
        /// �� ���������� �� ���������� ������ �������� ����.</intdoc>
        public override GostSharedSecretAlgorithm CreateAgree(
            Gost3410Parameters alg)
        {
            // ���������� ��� � ������ ��� ��������.
            Gost3410CspObject obj1 = new Gost3410CspObject(alg);

            return new GostSharedSecretCryptoServiceProvider(_safeKeyHandle,
                _safeProvHandle, obj1, CspAlgorithmType.Gost2001);
        }

        /// <summary>
        /// ������������ �������� ������� ����������� ������.
        /// </summary>
        /// 
        /// <param name="disposing"><see langword="true"/>, ���� �������� 
        /// ������ � ������ ��������, <see langword="false"/> - ������ 
        /// ������� ����� ���� ����������.
        /// </param>
        protected override void Dispose(bool disposing)
        {
            if ((_safeKeyHandle != null) && !_safeKeyHandle.IsClosed)
                _safeKeyHandle.Dispose();
            if ((_safeProvHandle != null) && !_safeProvHandle.IsClosed)
                _safeProvHandle.Dispose();

            base.Dispose(disposing);
        }        

        private SafeProvHandle AcquireSafeProviderHandle()
        {
            SafeProvHandle safeProvHandleTemp;
            CapiHelper.AcquireCsp(new CspParameters(GostConstants.PROV_GOST_2001_DH), out safeProvHandleTemp);
            return safeProvHandleTemp;
        }

        public override byte[] SignHash(byte[] hash)
        {
            throw new NotSupportedException();
        }

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm)
        {
            throw new NotSupportedException();
        }

        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm)
        {
            throw new NotSupportedException();
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            throw new NotSupportedException();
        }

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            throw new NotSupportedException();
        }
    }
}
