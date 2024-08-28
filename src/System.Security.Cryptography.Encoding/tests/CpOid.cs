// <copyright file="OidTest.cs" company="Крипто-Про">
// Copyright (c) Крипто-Про. Все права защищены.
// </copyright>

using System.Collections.Generic;
using System.Runtime.InteropServices;
using Xunit;

namespace System.Security.Cryptography.Encoding.Tests
{
    public class CpOidTests
    {
        [Fact]
        public void TestOidConstructorValue()
        {
            var oid = new Oid("1.2.643.7.1.1.2.2");
            Assert.Equal("1.2.643.7.1.1.2.2", oid.Value);
            Assert.Equal("ГОСТ Р 34.11-2012 256 бит", oid.FriendlyName);
        }

        [Fact]
        public void TestOidConstructorFriendlyName()
        {
            var oid = new Oid("ГОСТ Р 34.11-2012 256 бит");
            Assert.Equal("1.2.643.7.1.1.2.2", oid.Value);
            Assert.Equal("ГОСТ Р 34.11-2012 256 бит", oid.FriendlyName);
        }

        [Fact]
        public void TestOidConstructorValueWithFriendlyName()
        {
            var oid = new Oid("1.2.643.7.1.1.2.2", "ГОСТ Р 34.11-2012 256 бит");
            Assert.Equal("1.2.643.7.1.1.2.2", oid.Value);
            Assert.Equal("ГОСТ Р 34.11-2012 256 бит", oid.FriendlyName);
        }

        [Fact]
        public void TestFromOidValueHash()
        {
            var oid = Oid.FromOidValue(
                "1.2.643.7.1.1.2.2",
                System.Security.Cryptography.OidGroup.HashAlgorithm);
            Assert.Equal("1.2.643.7.1.1.2.2", oid.Value);
            Assert.Equal("ГОСТ Р 34.11-2012 256 бит", oid.FriendlyName);
        }

        [Fact]
        public void TestFromOidValueAll()
        {
            var oid = Oid.FromOidValue(
                "1.2.643.7.1.1.2.2",
                System.Security.Cryptography.OidGroup.All);
            Assert.Equal("1.2.643.7.1.1.2.2", oid.Value);
            Assert.Equal("ГОСТ Р 34.11-2012 256 бит", oid.FriendlyName);
        }

        [Fact]
        public void TestFromFriendlyNameHash()
        {
            var oid = Oid.FromFriendlyName(
                "ГОСТ Р 34.11-2012 256 бит",
                System.Security.Cryptography.OidGroup.HashAlgorithm);
            Assert.Equal("1.2.643.7.1.1.2.2", oid.Value);
            Assert.Equal("ГОСТ Р 34.11-2012 256 бит", oid.FriendlyName);
        }

        [Fact]
        public void TestFromFriendlyNameAll()
        {
            var oid = Oid.FromFriendlyName(
                "ГОСТ Р 34.11-2012 256 бит",
                System.Security.Cryptography.OidGroup.All);
            Assert.Equal("1.2.643.7.1.1.2.2", oid.Value);
            Assert.Equal("ГОСТ Р 34.11-2012 256 бит", oid.FriendlyName);
        }
    }
}
