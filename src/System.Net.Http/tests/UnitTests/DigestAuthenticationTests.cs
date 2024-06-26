﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace System.Net.Http.Tests
{
    public class DigestAuthenticationTests
    {
        private static readonly List<string> s_keyListWithCountTwo = new List<string> { "key1", "key2" };
        private static readonly List<string> s_valueListWithCountTwo = new List<string> { "value1", "value2" };
        private static readonly List<string> s_listWithCountOne = new List<string> { "item1" };
        private static readonly List<string> s_emptyStringList = new List<string>();

        [Theory]
        [MemberData(nameof(DigestResponse_Challenge_TestData))]
        public void DigestResponse_Parse_Succeeds(string challenge, List<string> keys, List<string> values)
        {
            AuthenticationHelper.DigestResponse digestResponse = new AuthenticationHelper.DigestResponse(challenge);
            Assert.Equal(keys.Count, digestResponse.Parameters.Count);
            Assert.Equal(values.Count, digestResponse.Parameters.Count);
            Assert.Equal(keys, digestResponse.Parameters.Keys);
            Assert.Equal(values, digestResponse.Parameters.Values);
        }

        public static IEnumerable<object[]> DigestResponse_Challenge_TestData()
        {
            yield return new object[] { "key1=value1,key2=value2", s_keyListWithCountTwo, s_valueListWithCountTwo };
            yield return new object[] { "\tkey1===value1,key2 \t===\tvalue2", s_keyListWithCountTwo, s_valueListWithCountTwo };
            yield return new object[] { "    key1 = value1, key2 =    value2,", s_keyListWithCountTwo, s_valueListWithCountTwo };
            yield return new object[] { "item1 === item1,key2=, value2", s_listWithCountOne, s_listWithCountOne };
            yield return new object[] { "item1,==item1,,,    key2=\"value2\", key3 m", new List<string> { "item1," }, s_listWithCountOne };
            yield return new object[] { "key1= \"value1   \",key2  =  \"v alu#e2\"   ,", s_keyListWithCountTwo, new List<string> { "value1   ", "v alu#e2" } };
            yield return new object[] { "key1   ", s_emptyStringList, s_emptyStringList };
            yield return new object[] { "=====", s_emptyStringList, s_emptyStringList };
            yield return new object[] { ",,", s_emptyStringList, s_emptyStringList };
            yield return new object[] { "=,=", s_emptyStringList, s_emptyStringList };
            yield return new object[] { "=value1,key2=,", s_emptyStringList, s_emptyStringList };
            yield return new object[] { "key1\tm= value1", s_emptyStringList, s_emptyStringList };
        }

        [Theory]
        [InlineData("realm=\"NetCore\", nonce=\"qMRqWgAAAAAQMjIABgAAAFwEiEwAAAAA\", qop=\"auth\", stale=false", true)]
        [InlineData("realm=\"NetCore\", nonce=\"qMRqWgAAAAAQMjIABgAAAFwEiEwAAAAA\"", true)]
        [InlineData("nonce=\"qMRqWgAAAAAQMjIABgAAAFwEiEwAAAAA\", qop=\"auth\", stale=false", false)]
        [InlineData("realm=\"NetCore\", qop=\"auth\", stale=false", false)]
        public async Task DigestResponse_AuthToken_Handling(string response, bool expectedResult)
        {
            NetworkCredential credential = new NetworkCredential("foo","PLACEHOLDER");
            AuthenticationHelper.DigestResponse digestResponse = new AuthenticationHelper.DigestResponse(response);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, "http://microsoft.com/");
            string parameter = await AuthenticationHelper.GetDigestTokenForCredential(credential, request, digestResponse).ConfigureAwait(false);

            Assert.Equal(expectedResult, parameter != null);
        }

        [Theory]
        [InlineData("test", "username=\"test\"")]
        [InlineData("test@example.org", "username=\"test@example.org\"")]
        [InlineData("test\"example.org", "username=\"test\\\"example.org\"")]
        [InlineData("t\u00E6st", "username*=utf-8''t%C3%A6st")]
        [InlineData("\uD834\uDD1E", "username*=utf-8''%F0%9D%84%9E")]
        public async Task DigestResponse_UserName_Encoding(string username, string encodedUserName)
        {
            NetworkCredential credential = new NetworkCredential(username, "bar");
            AuthenticationHelper.DigestResponse digestResponse = new AuthenticationHelper.DigestResponse("realm=\"NetCore\", nonce=\"qMRqWgAAAAAQMjIABgAAAFwEiEwAAAAA\"");
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, "http://microsoft.com/");
            string parameter = await AuthenticationHelper.GetDigestTokenForCredential(credential, request, digestResponse).ConfigureAwait(false);
            Assert.StartsWith(encodedUserName, parameter);
        }

        public static IEnumerable<object[]> DigestResponse_ShouldSendQop_TestData()
        {
            yield return new object[] { "realm=\"NetCore\", nonce=\"qMRqWgAAAAAQMjIABgAAAFwEiEwAAAAA\", qop=\"auth\", stale=false", "(?=.*username=)(?=.*realm=)(?=.*nonce=)(?=.*uri=)(?=.*response=)(?=.*qop=)(?=.*nc=)(?=.*cnonce=)", "(opaque=|algorithm=)", 8 };
            yield return new object[] { "realm=\"NetCore\", nonce=\"qMRqWgAAAAAQMjIABgAAAFwEiEwAAAAA\", stale=false", "(?=.*username=)(?=.*realm=)(?=.*nonce=)(?=.*uri=)(?=.*response=)", "(qop=|cnonce=|opaque=|algorithm=)", 5 };
            yield return new object[] { "realm=\"NetCore\", nonce=\"qMRqWgAAAAAQMjIABgAAAFwEiEwAAAAA\", stale=false, algorithm=MD5", "(?=.*username=)(?=.*realm=)(?=.*nonce=)(?=.*uri=)(?=.*response=)(?=.*algorithm=)", null, 6 };
            yield return new object[] { "realm=\"NetCore\", nonce=\"qMRqWgAAAAAQMjIABgAAAFwEiEwAAAAA\", qop=\"auth\", stale=false, opaque=\"qMRqWgAAAAAA\"", "(?=.*username=)(?=.*realm=)(?=.*nonce=)(?=.*uri=)(?=.*response=)(?=.*qop=)(?=.*nc=)(?=.*cnonce=)(?=.*opaque=)", "(algorithm=)", 9 };
            yield return new object[] { "realm=\"NetCore\", nonce=\"qMRqWgAAAAAQMjIABgAAAFwEiEwAAAAA\", stale=false, opaque=\"qMRqWgAAAAAA\"", "(?=.*username=)(?=.*realm=)(?=.*nonce=)(?=.*uri=)(?=.*response=)(?=.*opaque=)", "(algorithm=)", 6 };
            yield return new object[] { "realm=\"NetCore\", nonce=\"qMRqWgAAAAAQMjIABgAAAFwEiEwAAAAA\", stale=false, algorithm=MD5-sess, qop=\"auth\"", "(?=.*username=)(?=.*realm=)(?=.*nonce=)(?=.*uri=)(?=.*response=)(?=.*qop=)(?=.*nc=)(?=.*cnonce=)(?=.*algorithm=)", null, 9 };
            yield return new object[] { "realm=\"NetCore\", nonce=\"qMRqWgAAAAAQMjIABgAAAFwEiEwAAAAA\", opaque=\"qMRqWgAAAAAA\", stale=false, algorithm=MD5-sess, qop=\"auth\"", "(?=.*username=)(?=.*realm=)(?=.*nonce=)(?=.*uri=)(?=.*response=)(?=.*qop=)(?=.*nc=)(?=.*cnonce=)(?=.*algorithm=)(?=.*opaque=)", null, 10 };
            yield return new object[] { "realm=\"NetCore\", nonce=\"qMRqWgAAAAAQMjIABgAAAFwEiEwAAAAA\", opaque=\"\", stale=false, algorithm=MD5, qop=\"auth\"", "(?=.*username=)(?=.*realm=)(?=.*nonce=)(?=.*uri=)(?=.*response=)(?=.*qop=)(?=.*nc=)(?=.*cnonce=)(?=.*algorithm=)(?=.*opaque=)", null, 10 };
        }

        [Theory]
        [MemberData(nameof(DigestResponse_ShouldSendQop_TestData))]
        public async Task DigestResponse_ShouldSendQop(string response, string match, string doesNotMatch, int fieldCount)
        {
            NetworkCredential credential = new NetworkCredential("foo", "bar");
            AuthenticationHelper.DigestResponse digestResponse = new AuthenticationHelper.DigestResponse(response);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, "http://microsoft.com/");
            string parameter = await AuthenticationHelper.GetDigestTokenForCredential(credential, request, digestResponse).ConfigureAwait(false);
            if (match != null)
            { 
                Assert.Matches(match, parameter);
            }
            if (doesNotMatch != null)
            { 
                Assert.DoesNotMatch(doesNotMatch, parameter);
            }
            Assert.Equal(fieldCount, parameter.Split(',').Length);
            Assert.False(parameter.Trim().EndsWith(","));
        }
    }
}
