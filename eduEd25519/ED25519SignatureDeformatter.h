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
	public ref class ED25519SignatureDeformatter : Security::Cryptography::AsymmetricSignatureDeformatter
	{
	public:
		ED25519SignatureDeformatter()
		{
		}

		ED25519SignatureDeformatter(Security::Cryptography::AsymmetricAlgorithm ^key)
		{
			ED25519SignatureDeformatter::SetKey(key);
		}

		virtual void SetKey(Security::Cryptography::AsymmetricAlgorithm ^key) override
		{
			m_key = dynamic_cast<ED25519^>(key);
			if (m_key == nullptr)
				throw gcnew ArgumentException(); // TODO: Make error message using resources.
		}

		virtual void SetHashAlgorithm(String ^name) override
		{
			// ED25519SignatureDeformatter always uses SHA512 algorithm.
			if (name->ToUpper()->CompareTo(L"SHA512") != 0)
				throw gcnew ArgumentException(); // TODO: Make error message using resources.
		}

		virtual bool VerifySignature(array<unsigned char> ^hash, cli::array<unsigned char> ^signature) override
		{
			// Extract hash.
			int ph_size = hash->Length;
			unsigned char *ph_buffer = new unsigned char[ph_size];
#pragma warning(suppress: 6001)
			Marshal::Copy(hash, 0, IntPtr(ph_buffer), ph_size);

			// Extract signature.
			int sig_size = signature->Length;
			unsigned char *sig_buffer = new unsigned char[sig_size];
#pragma warning(suppress: 6001)
			Marshal::Copy(signature, 0, IntPtr(sig_buffer), sig_size);

			// Verify the signature.
			return _crypto_sign_ed25519_verify_detached(sig_buffer, ph_buffer, ph_size, m_key->m_sk + crypto_sign_ed25519_SEEDBYTES, 1) == 0 ? true : false;
		}

	protected:
		ED25519^ m_key;
	};
}
