/*
    eduEd25519 - High-speed high-security signatures

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using eduEd25519.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace eduEd25519.Tests
{
    [TestClass()]
    public class SHA256Tests
    {
        [TestMethod()]
        public void SHA256Test()
        {
            eduEd25519.SHA256 hash = new eduEd25519.SHA256();

            CollectionAssert.AreEqual(
                Convert.FromBase64String($"qKL26+KGaXxSfrNaWLVTlTLps647ZNTrCkb7ZXtBViw="),
                hash.ComputeHash(Encoding.UTF8.GetBytes("This is a test.")));
        }

#if PLATFORM_AnyCPU
        private static bool is_resolver_active = eduBase.MultiplatformDllLoader.Enable = true;
#endif
    }
}
