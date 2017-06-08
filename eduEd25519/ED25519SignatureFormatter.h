/*
eduEd25519 - High-speed high-security signatures

Copyright: 2017, The Commons Conservancy eduVPN Programme
SPDX-License-Identifier: GPL-3.0+
*/

#pragma once

#include <sodium/crypto_sign_ed25519.h>
#include <sodium/utils.h>
extern "C" {
#include <libsodium/crypto_sign/ed25519/ref10/ed25519_ref10.h>
}

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
			// Extract hash.
			int ph_size = hash->Length;
			unsigned char *ph_buffer = new unsigned char[ph_size];
#pragma warning(suppress: 6001)
			Marshal::Copy(hash, 0, IntPtr(ph_buffer), ph_size);

			// Sign the hash.
			unsigned char sig[crypto_sign_ed25519_BYTES];
			unsigned long long siglen;
			_crypto_sign_ed25519_detached(sig, &siglen, ph_buffer, ph_size, m_key->m_sk, 1);
			delete[] ph_buffer;

			// Marshal to managed.
			array<unsigned char>^ result = gcnew array<unsigned char>(crypto_sign_ed25519_BYTES);
			Marshal::Copy(IntPtr(sig), result, 0, crypto_sign_ed25519_BYTES);
			return result;
		}

	protected:
		ED25519^ m_key;
	};
}
