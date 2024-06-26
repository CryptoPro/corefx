// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal partial class Interop
{
    internal static unsafe void GetRandomBytes(byte* buffer, int length)
    {
        if (!LocalAppContextSwitches.UseNonRandomizedHashSeed)
        {
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                byte[] tmp = new byte[length];
                rng.GetBytes(tmp);
                Marshal.Copy(tmp, 0, (IntPtr)buffer, length);
            }
        }
    }
}
