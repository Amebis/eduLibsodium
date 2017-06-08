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
    public class ED25519SignatureFormatterTests
    {
        [TestMethod()]
        public void ED25519SignatureFormatterTest()
        {
            // Create a new instance of ED25519.
            using (eduEd25519.ED25519 ed = new eduEd25519.ED25519())
            {
                // The hash to sign.
                byte[] hash;
                using (eduEd25519.SHA512 sha512 = new eduEd25519.SHA512())
                    hash = sha512.ComputeHash(Encoding.UTF8.GetBytes("This is a test."));

                // Create an ED25519SignatureFormatter object and pass it the
                // ED25519 to transfer the key information.
                ED25519SignatureFormatter ed_formatter = new ED25519SignatureFormatter(ed);

                // Set the hash algorithm to SHA512.
                ed_formatter.SetHashAlgorithm("SHA512");

                //Create a signature for hash and return it. 
                byte[] sig = ed_formatter.CreateSignature(hash);
            }
        }

        private static bool is_resolver_active = MultiplatformDllLoader.Enable = true;
    }
}