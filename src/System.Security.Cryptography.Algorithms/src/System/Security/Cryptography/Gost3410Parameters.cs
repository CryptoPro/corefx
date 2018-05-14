// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    /// <summary>
    /// ���������, ���������� ��������� ��������� ������� ���� � 34.10
    /// � ��������� ������������ ������ ���������� �����, �������
    /// �������� ����.
    /// </summary>
    /// <remarks>
    /// <para>��������� �������� ������ ���������� ��. 
    /// <a href="http://www.ietf.org/rfc/rfc4491.txt">RFC 4491</a>.</para>
    /// </remarks>
    /// 
    /// <basedon cref="System.Security.Cryptography.RSAParameters"/> 
    /// <basedon cref="System.Security.Cryptography.DSAParameters"/> 
    [StructLayout(LayoutKind.Sequential)]
    public struct Gost3410Parameters
    {
        /// <summary>OID ���������� ������� � DH.</summary>
        public string PublicKeyParamSet;
        /// <summary>OID ���������� �����������.</summary>
        public string DigestParamSet;
        /// <summary>�������������� OID ���������� ����������.</summary>
        public string EncryptionParamSet;
        /// <summary>�������� ����.</summary>
        public byte[] PublicKey;
        /// <summary>��������� ����.</summary>
        [NonSerialized]
        public byte[] PrivateKey;
    }
}
