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
    /// Алгоритм формирования общих ключей (SharedSecret) на основе 
    /// алгоритма ГОСТ Р 34.10,
    /// эфимерного ключа и Криптопровайдера.
    /// </summary>
    /// 
    /// <cspversions />
    public sealed class Gost3410EphemeralCryptoServiceProvider : Gost3410
    {
        /// <summary>
        /// HANDLE ключа.
        /// </summary>
        private SafeKeyHandle _safeKeyHandle;
        /// <summary>
        /// HANDLE провайдера.
        /// </summary>
        private SafeProvHandle _safeProvHandle;

        /// <summary>
        /// Получение текущего (не дубликата) HANDLE key.
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
        /// Получение текущего (не дубликата) HANDLE key.
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
        /// Получение текущего HANDLE провайдера без изменения RefCount.
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
        /// Получение текущего HANDLE провайдера без AddRef.
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
        /// Инициализация алгоритма с заданными параметрами. 
        /// </summary>
        /// <param name="basedOn">Параметры алгоритма, на основе которого
        /// будет сформирована секретная ключевая пара. Используется
        /// OID хэширования и открытого ключа, остальные параметры не 
        /// используются.</param>
        public Gost3410EphemeralCryptoServiceProvider(Gost3410Parameters basedOn)
        {
            _safeKeyHandle = SafeKeyHandle.InvalidHandle;
            _safeProvHandle = AcquireSafeProviderHandle();

            // Генерация эфимерного ключа без возможности экспорта бессмысленна.
            // Остальные флаги не тащим.
            CapiHelper.GenerateKey(_safeProvHandle,
                GostConstants.CALG_DH_EL_EPHEM, CspProviderFlags.NoFlags,
                GostConstants.GOST_3410EL_SIZE, basedOn.DigestParamSet,
                basedOn.PublicKeyParamSet, out _safeKeyHandle);
        }

        /// <summary>
        /// Инициализация алгоритма с параметрами заданными 
        /// внутри реализации CSP.
        /// </summary>
        public Gost3410EphemeralCryptoServiceProvider()
        {
            _safeKeyHandle = SafeKeyHandle.InvalidHandle;
            CapiHelper.GenerateKey(_safeProvHandle,
                GostConstants.CALG_DH_EL_EPHEM, (CspProviderFlags)0, 
                GostConstants.GOST_3410EL_SIZE, out _safeKeyHandle);
        }

    /// <summary>
    /// Экспорт параметров алгоритма.
    /// </summary>
    /// 
    /// <param name="includePrivateParameters"><see langword="true"/>, 
    /// для экспорта секретного ключа.</param>
    /// 
    /// <returns>Параметры алгоритма.</returns>
    /// 
    /// <exception cref="CryptographicException">При экспорте
    /// секретного ключа.</exception>
    /// 
    /// <remarks>
    /// <if notdefined="userexp"><para>По соображениям безопасности 
    /// в данной сборке при экспорте 
    /// секретного ключа всегда возбуждает исключение 
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
    /// Импорт параметров алгоритма.
    /// </summary>
    /// 
    /// <param name="parameters">Параметры алгоритма.</param>
    /// 
    /// <exception cref="CryptographicException">Всегда.
    /// </exception>
    public override void ImportParameters(Gost3410Parameters parameters)
    {
        // Импорт открытого ключа - это создание agree, 
        // Переустановка параметров не поддерживается.
        // Имеет смысл реализовывать только импорт private
        throw new NotSupportedException();
    }

        /// <summary>
        /// Создание ключа согласования.
        /// </summary>
        /// 
        /// <param name="alg">Параметры открытого ключа.</param>
        /// 
        /// <returns>Распределенный секрет.</returns>
        /// 
        /// <intdoc>Не проверяем возможность SharedSecret,
        /// мы используем из контейнера только открытый ключ.</intdoc>
        public override GostSharedSecretAlgorithm CreateAgree(
            Gost3410Parameters alg)
        {
            // Превращаем его в объект для экспорта.
            Gost3410CspObject obj1 = new Gost3410CspObject(alg);

            return new GostSharedSecretCryptoServiceProvider(_safeKeyHandle,
                _safeProvHandle, obj1, CspAlgorithmType.Gost2001);
        }

        /// <summary>
        /// Освобождение ресурсов занятых экземпляром класса.
        /// </summary>
        /// 
        /// <param name="disposing"><see langword="true"/>, если разрешен 
        /// доступ к другим объектам, <see langword="false"/> - другие 
        /// объекты могут быть уничтожены.
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
