/*
    eduEd25519 - High-speed high-security signatures

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using eduEd25519Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace eduEd25519.Tests
{
    [TestClass()]
    public class SHA512Tests
    {
        [TestMethod()]
        public void SHA512Test()
        {
            eduEd25519.SHA512 hash = new eduEd25519.SHA512();

            CollectionAssert.AreEqual(
                Convert.FromBase64String($"87+apwFp5KtTOfIHWJhlOP5slte+PRhKA2zegWEQX89TUWQo+glqxWJHu4gIWwWH1eyOVqaAexrzUTBbIQPXSw=="),
                hash.ComputeHash(Encoding.UTF8.GetBytes("This is a test.")));
        }

#if PLATFORM_AnyCPU
        private static bool is_resolver_active = MultiplatformDllLoader.Enable = true;
#endif
    }
}
