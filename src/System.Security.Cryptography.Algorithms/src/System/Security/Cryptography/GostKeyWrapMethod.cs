// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    /// <summary>
    /// �������� ������������ ���������� �����.
    /// </summary>
    public enum GostKeyWrapMethod
    {
        /// <summary>
        /// ������� ������� ����� �� ���� 28147-89.
        /// </summary>
        GostKeyWrap,

        /// <summary>
        /// ���������� ������� ����� �� ��������� ���������.
        /// </summary>
        CryptoProKeyWrap,

        /// <summary>
        /// ���������� ������� ����� �� ��������� ���������12.
        /// </summary>
        CryptoPro12KeyWrap,
    }
}
