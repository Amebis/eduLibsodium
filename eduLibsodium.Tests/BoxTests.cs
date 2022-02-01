/*
    eduLibsodium - .NET Framework-libsodium bridge

    Copyright: 2022 The Commons Conservancy
    SPDX-License-Identifier: GPL-3.0+
*/

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace eduLibsodium.Tests
{
    class BoxTests
    {
        [TestMethod()]
        public void BoxSerializationTest()
        {
            using (var key = new Box())
            {
                using (var keyImp = new Box())
                {
                    keyImp.FromXmlString(key.ToXmlString(true));
                    CollectionAssert.AreEqual(key.PublicKey, keyImp.PublicKey);
                    CollectionAssert.AreEqual(key.SecretKey, keyImp.SecretKey);
                }

                using (var keyImp = new Box())
                {
                    keyImp.FromXmlString(key.ToXmlString(false));
                    CollectionAssert.AreEqual(key.PublicKey, keyImp.PublicKey);
                    CollectionAssert.AreEqual(null, keyImp.SecretKey);
                }
            }
        }
    }
}
