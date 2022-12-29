﻿/*
    eduLibsodium - .NET Framework-libsodium bridge

    Copyright: 2017-2023 The Commons Conservancy
    SPDX-License-Identifier: GPL-3.0+
*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace eduLibsodium.Tests
{
    [TestClass()]
    public class ED25519Tests
    {
        [TestMethod()]
        public void ED25519SerializationTest()
        {
            byte[]
                data = Encoding.UTF8.GetBytes("This is a test."),
                smsg;
            string
                xml,
                xml_pub;

            using (var key = new ED25519())
            {
                // Sign data.
                smsg = key.SignCombined(data);

                // Export.
                xml = key.ToXmlString(true);
                xml_pub = key.ToXmlString(false);
            }

            using (var key = new ED25519())
            {
                key.FromXmlString(xml);

                // Sign data and compare.
                CollectionAssert.AreEqual(smsg, key.SignCombined(data));
            }

            using (var key = new ED25519())
            {
                key.FromXmlString(xml_pub);

                // Verify signature.
                byte[] data2 = null;
                Assert.IsTrue(key.VerifyCombined(smsg, ref data2));
                CollectionAssert.AreEqual(data, data2);
            }
        }

        [TestMethod()]
        public void ED25519PublicKeyTest()
        {
            byte[]
                data = Encoding.UTF8.GetBytes("This is a test."),
                smsg,
                pub_key;

            using (var key = new ED25519())
            {
                // Sign data.
                smsg = key.SignCombined(data);

                // Get public key.
                pub_key = key.PublicKey;
            }

            using (var key = new ED25519(pub_key))
            {
                // Verify signature.
                byte[] data2 = null;
                Assert.IsTrue(key.VerifyCombined(smsg, ref data2));
                CollectionAssert.AreEqual(data, data2);
            }
        }

        [TestMethod()]
        public void ED25519CombinedTest()
        {
            var data = Encoding.UTF8.GetBytes("This is a test.");

            using (var key = new ED25519())
            {
                // Sign data.
                var smsg = key.SignCombined(data);

                // Verify signature.
                byte[] data2 = null;
                Assert.IsTrue(key.VerifyCombined(smsg, ref data2));
                CollectionAssert.AreEqual(data, data2);

                // Alter data and re-verify.
                smsg[smsg.Length - 1] ^= 0x01;
                Assert.IsFalse(key.VerifyCombined(smsg, ref data2));
            }
        }

        [TestMethod()]
        public void ED25519DetachedTest()
        {
            var data = Encoding.UTF8.GetBytes("This is a test.");

            using (var key = new ED25519())
            {
                // Sign data.
                var sig = key.SignDetached(data);

                // Verify signature.
                Assert.IsTrue(key.VerifyDetached(data, sig));

                // Alter data and re-verify.
                sig[sig.Length - 1] ^= 0x01;
                Assert.IsFalse(key.VerifyDetached(data, sig));
            }
        }

#if PLATFORM_AnyCPU
        private static bool is_resolver_active = eduBase.MultiplatformDllLoader.Enable = true;
#endif
    }
}
