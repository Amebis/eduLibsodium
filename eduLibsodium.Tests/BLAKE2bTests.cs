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
    public class BLAKE2bTests
    {
        [TestMethod()]
        public void BLAKE2bTest()
        {
            var hash = new BLAKE2b(512);
            CollectionAssert.AreEqual(
                Convert.FromBase64String($"c+zZSGWOn2QFPsY44AMjM7RHRd0/O0a6PbHlCjC41pVdACGhcYBzvEIYg/R276CxtU9s7LN0LN7eFFqdC2HgGA=="),
                hash.ComputeHash(Encoding.UTF8.GetBytes("This is a test.")));

            hash = new BLAKE2b(160);
            CollectionAssert.AreEqual(
                Convert.FromBase64String($"Qab6xFFRC6sedzhR144l2p7PHeE="),
                hash.ComputeHash(Encoding.UTF8.GetBytes("This is a test.")));
        }

#if PLATFORM_AnyCPU
        private static bool is_resolver_active = eduBase.MultiplatformDllLoader.Enable = true;
#endif
    }
}
