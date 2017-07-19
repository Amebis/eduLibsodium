/*
    eduEd25519 - High-speed high-security signatures

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using eduEd25519.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace eduEd25519.Tests
{
    [TestClass()]
    public class ED25519Tests
    {
        [TestMethod()]
        public void ED25519TestCombined()
        {
            byte[] data = Encoding.UTF8.GetBytes("This is a test.");

            using (eduEd25519.ED25519 key = new eduEd25519.ED25519())
            {
                // Sign data.
                byte[] smsg = key.SignCombined(data);

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
        public void ED25519TestDetached()
        {
            byte[] data = Encoding.UTF8.GetBytes("This is a test.");

            using (eduEd25519.ED25519 key = new eduEd25519.ED25519())
            {
                // Sign data.
                byte[] sig = key.SignDetached(data);

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
