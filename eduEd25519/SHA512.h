/*
eduEd25519 - High-speed high-security signatures

Copyright: 2017, The Commons Conservancy eduVPN Programme
SPDX-License-Identifier: GPL-3.0+
*/

#pragma once

#include <sodium/crypto_hash_sha512.h>

using namespace System;
using namespace System::Runtime::InteropServices;

namespace eduEd25519
{
	public ref class SHA512 : Security::Cryptography::HashAlgorithm
	{
	public:
		SHA512()
		{
			// Create hash.
			m_state = new crypto_hash_sha512_state;

			// Initialize hash.
			crypto_hash_sha512_init(m_state);
		}

		~SHA512() {}

		!SHA512()
		{
			delete m_state;
		}

		virtual void Initialize() override
		{
			// Initialize hash.
			crypto_hash_sha512_init(m_state);
		}

	protected:
		virtual void HashCore(array<unsigned char> ^data, int start, int size) override
		{
			// Extract, hash, delete.
			unsigned char *buffer = new unsigned char[size];
			Marshal::Copy(data, start, IntPtr(buffer), size);
			crypto_hash_sha512_update(m_state, buffer, size);
			delete[] buffer;
		}

		virtual array<unsigned char>^ HashFinal() override
		{
			// Finalize and get hash value.
			unsigned char buffer[crypto_hash_sha512_BYTES];
			crypto_hash_sha512_final(m_state, buffer);

			// Marshal to managed.
			array<unsigned char>^ result = gcnew array<unsigned char>(crypto_hash_sha512_BYTES);
			Marshal::Copy(IntPtr(buffer), result, 0, crypto_hash_sha512_BYTES);
			return result;
		}

	protected:
		crypto_hash_sha512_state* m_state;
	};
}
