/*
    eduLibsodium - .NET Framework-libsodium bridge

    Copyright: 2017 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace eduLibsodium.Tests
{
    [TestClass()]
    public class SHA512Tests
    {
        [TestMethod()]
        public void SHA512Test()
        {
            var hash = new SHA512();

            CollectionAssert.AreEqual(
                Convert.FromBase64String($"87+apwFp5KtTOfIHWJhlOP5slte+PRhKA2zegWEQX89TUWQo+glqxWJHu4gIWwWH1eyOVqaAexrzUTBbIQPXSw=="),
                hash.ComputeHash(Encoding.UTF8.GetBytes("This is a test.")));
        }

#if PLATFORM_AnyCPU
        private static bool is_resolver_active = eduBase.MultiplatformDllLoader.Enable = true;
#endif
    }
}
