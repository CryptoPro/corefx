﻿using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Класc формирования подписи на алгоритме ГОСТ Р 34.10-2012 256.
    /// </summary>
    ///
    /// <remarks>
    /// Создает подпись, на алгоритме ГОСТ Р 34.10-2012 256. Для проверки подписи
    /// существует класс GostSignatureDeformatter.
    /// </remarks>
    ///
    /// <doc-sample path="Simple\DocBlock" name="SignatureFormatter2012_256"
    /// region="SignatureFormatter2012_256">Пример, вычисления подписи при помощи
    /// <c>GostSignatureFormatter</c>.</doc-sample>
    ///
    /// <basedon cref="System.Security.Cryptography.RSAPKCS1SignatureFormatter"/>
    /// <basedon cref="System.Security.Cryptography.DSASignatureFormatter"/>
    [ComVisible(true)]
    public class Gost2012_256SignatureDeformatter : AsymmetricSignatureDeformatter
    {
        /// <summary>
        /// Ключ.
        /// </summary>
        private Gost3410_2012_256 _gostKey;

        /// <summary>
        /// OID алгоритма хэширования.
        /// </summary>
        private string _alg_algOid;

        /// <summary>
        /// Создание объекта класса <see cref="Gost2012_256SignatureDeformatter"/>.
        /// </summary>
        public Gost2012_256SignatureDeformatter()
        {
            _alg_algOid = CryptoConfig.MapNameToOID("GOST3411_2012_256");
        }

        /// <summary>
        /// Создание объекта класса <see cref="Gost2012_256SignatureDeformatter"/>
        /// с заданным ключом.
        /// </summary>
        ///
        /// <param name="key">Провайдер, содержащий ключ.</param>
        ///
        /// <doc-sample path="Simple\DocBlock" name="SignatureFormatter2012_256"
        /// region="SignatureFormatter2012_256">Пример, вычисления подписи при
        /// помощи GostSignatureFormatter.</doc-sample>
        ///
        /// <argnull name="key" />
        /// <exception cref="CryptographicException">Параметр
        /// <paramref name="key"/> не является реализацией
        /// алгоритма ГОСТ Р 34.10-2012 256.</exception>
        public Gost2012_256SignatureDeformatter(AsymmetricAlgorithm key)
            : this()
        {
            if (key == null)
                throw new ArgumentNullException("key");
            Gost3410_2012_256 gost = key as Gost3410_2012_256;
            if (gost == null)
                throw new ArgumentNullException(nameof(gost));
            _gostKey = gost;
        }

        /// <summary>
        /// Создает подпись на значение хэш-функции.
        /// </summary>
        ///
        /// <param name="rgbHash">Подписываемый хэш.</param>
        ///
        /// <returns>Подпись для <paramref name="rgbHash"/></returns>
        ///
        /// <remarks><para>
        /// Ключ и алгоритм хэширования должны быть определены до вызова
        /// этого метода.</para></remarks>
        ///
        /// <doc-sample path="Simple\DocBlock" name="SignatureFormatter2012_256"
        /// region="SignatureFormatter2012_256">Пример, вычисления подписи при помощи
        /// <c>GostSignatureFormatter</c>.</doc-sample>
        ///
        /// <exception cref="CryptographicUnexpectedOperationException">
        /// Не установлен алгоритм хэширования или ключ</exception>
        /// <argnull name="rgbHash" />
        public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
        {
            if (rgbHash == null)
                throw new ArgumentNullException(nameof(rgbHash));
            if (_alg_algOid == null)
                throw new CryptographicUnexpectedOperationException(SR.Cryptography_MissingOID);
            if (_gostKey == null)
                throw new CryptographicUnexpectedOperationException(SR.Cryptography_MissingKey);
            // Do we need it now?
            //byte[] rev = (byte[])rgbSignature.Clone();
            //Array.Reverse(rev);
            return _gostKey.VerifyHash(rgbHash, rgbSignature, HashAlgorithmName.Gost3411_2012_256);
        }

        /// <summary>
        /// Устанавливает алгоритм хэширования, используемый при создании
        /// подписи.
        /// </summary>
        ///
        /// <param name="strName">Название алгоритма.</param>
        ///
        /// <exception cref="CryptographicUnexpectedOperationException">
        /// Устанавливаемое имя алгоритма неизвестно или не поддерживает
        /// алгоритм ГОСТ Р 34.11-2012 256.</exception>
        public override void SetHashAlgorithm(string strName)
        {
            if (CryptoConfig.MapNameToOID(strName) != this._alg_algOid)
                throw new CryptographicUnexpectedOperationException(
                    SR.Cryptography_InvalidOperation);
        }

        /// <summary>
        /// Устанавливает ключ, используемый при создании подписи.
        /// </summary>
        ///
        /// <param name="key">Объект, содержащий ключ.</param>
        ///
        /// <argnull name="key" />
        /// <exception cref="CryptographicException">Параметр
        /// <paramref name="key"/> не является реализацией
        /// алгоритма ГОСТ Р 34.10-2012 256.</exception>
        public override void SetKey(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            Gost3410_2012_256 gost = key as Gost3410_2012_256;
            if (gost == null)
                throw new ArgumentNullException(
                    nameof(gost));
            _gostKey = gost;
        }
    }
}
