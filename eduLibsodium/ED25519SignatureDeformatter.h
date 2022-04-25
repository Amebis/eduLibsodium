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
	public ref class ED25519SignatureDeformatter : Security::Cryptography::AsymmetricSignatureDeformatter
	{
	public:
		ED25519SignatureDeformatter()
		{
		}

		ED25519SignatureDeformatter(Security::Cryptography::AsymmetricAlgorithm^ key)
		{
			ED25519SignatureDeformatter::SetKey(key);
		}

		virtual void SetKey(Security::Cryptography::AsymmetricAlgorithm^ key) override
		{
			m_key = dynamic_cast<ED25519^>(key);
			if (m_key == nullptr)
				throw gcnew ArgumentNullException(L"key");
		}

		virtual void SetHashAlgorithm(String^ name) override
		{
			// ED25519SignatureDeformatter always uses SHA512 algorithm.
			if (name->ToUpper()->CompareTo(L"SHA512") != 0)
				throw gcnew ArgumentException(String::Format(GetResourceString(L"ErrorUnsupportedHash"), name), L"name");
		}

		virtual bool VerifySignature(array<unsigned char>^ hash, array<unsigned char>^ signature) override
		{
			return m_key->VerifyHash(hash, signature);
		}

	protected:
		ED25519^ m_key;
	};
}
