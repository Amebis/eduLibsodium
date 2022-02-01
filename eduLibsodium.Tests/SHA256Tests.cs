/*
    eduLibsodium - .NET Framework-libsodium bridge

    Copyright: 2017 The Commons Conservancy
    SPDX-License-Identifier: GPL-3.0+
*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace eduLibsodium.Tests
{
    [TestClass()]
    public class SHA256Tests
    {
        [TestMethod()]
        public void SHA256Test()
        {
            var hash = new eduLibsodium.SHA256();

            CollectionAssert.AreEqual(
                Convert.FromBase64String($"qKL26+KGaXxSfrNaWLVTlTLps647ZNTrCkb7ZXtBViw="),
                hash.ComputeHash(Encoding.UTF8.GetBytes("This is a test.")));
        }

#if PLATFORM_AnyCPU
        private static bool is_resolver_active = eduBase.MultiplatformDllLoader.Enable = true;
#endif
    }
}
