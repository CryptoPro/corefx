// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Структура, содержащая параметры алгоритма подписи ГОСТ Р 34.10
    /// и алгоритма формирования общего секретного ключа, включая
    /// открытый ключ.
    /// </summary>
    /// <remarks>
    /// <para>Подробное описание набора параметров см. 
    /// <a href="http://www.ietf.org/rfc/rfc4491.txt">RFC 4491</a>.</para>
    /// </remarks>
    /// 
    /// <basedon cref="System.Security.Cryptography.RSAParameters"/> 
    /// <basedon cref="System.Security.Cryptography.DSAParameters"/> 
    [Serializable, StructLayout(LayoutKind.Sequential)]
    public struct Gost3410Parameters
    {
        /// <summary>OID параметров подписи и DH.</summary>
        public string PublicKeyParamSet;
        /// <summary>OID параметров хеширования.</summary>
        public string DigestParamSet;
        /// <summary>Необязательный OID параметров шифрования.</summary>
        public string EncryptionParamSet;
        /// <summary>Открытый ключ.</summary>
        public byte[] PublicKey;
        /// <summary>Секретный ключ.</summary>
        [NonSerialized]
        public byte[] PrivateKey;
    }
}
