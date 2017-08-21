/*
	eduEd25519 - High-speed high-security signatures

	Copyright: 2017, The Commons Conservancy eduVPN Programme
	SPDX-License-Identifier: GPL-3.0+
*/

#pragma once

// When libsodium include files are not found, read the chapter "Compiling libsodium" in README.md first.
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/utils.h>

using namespace System;
using namespace System::Runtime::InteropServices;

namespace eduEd25519
{
	public ref class ED25519SignatureFormatter : Security::Cryptography::AsymmetricSignatureFormatter
	{
	public:
		ED25519SignatureFormatter()
		{
		}

		ED25519SignatureFormatter(Security::Cryptography::AsymmetricAlgorithm ^key)
		{
			ED25519SignatureFormatter::SetKey(key);
		}

		virtual void SetKey(Security::Cryptography::AsymmetricAlgorithm ^key) override
		{
			m_key = dynamic_cast<ED25519^>(key);
			if (m_key == nullptr)
				throw gcnew ArgumentException(); // TODO: Make error message using resources.
		}

		virtual void SetHashAlgorithm(String ^name) override
		{
			// ED25519SignatureFormatter always uses SHA512 algorithm.
			if (name->ToUpper()->CompareTo(L"SHA512") != 0)
				throw gcnew ArgumentException(); // TODO: Make error message using resources.
		}

		virtual array<unsigned char>^ CreateSignature(array<unsigned char> ^hash) override
		{
			return m_key->SignHash(hash);
		}

	protected:
		ED25519^ m_key;
	};
}
