/*
	eduLibsodium - .NET Framework-libsodium bridge

	Copyright: 2017 The Commons Conservancy
	SPDX-License-Identifier: GPL-3.0+
*/

#pragma once

#include "eduLibsodium.h"

// When libsodium include files are not found, read the chapter "Compiling libsodium" in README.md first.
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/utils.h>

using namespace System;
using namespace System::Runtime::InteropServices;

namespace eduLibsodium
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
				throw gcnew ArgumentNullException(L"key");
		}

		virtual void SetHashAlgorithm(String ^name) override
		{
			// ED25519SignatureFormatter always uses SHA512 algorithm.
			if (name->ToUpper()->CompareTo(L"SHA512") != 0)
				throw gcnew ArgumentException(String::Format(GetResourceString(L"ErrorUnsupportedHash"), name), L"name");
		}

		virtual array<unsigned char>^ CreateSignature(array<unsigned char> ^hash) override
		{
			return m_key->SignHash(hash);
		}

	protected:
		ED25519^ m_key;
	};
}
