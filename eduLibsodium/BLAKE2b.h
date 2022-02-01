/*
	eduLibsodium - .NET Framework-libsodium bridge

	Copyright: 2017 The Commons Conservancy
	SPDX-License-Identifier: GPL-3.0+
*/

#pragma once

// When libsodium include files are not found, read the chapter "Compiling libsodium" in README.md first.
#include <sodium/crypto_generichash_blake2b.h>

using namespace System;
using namespace System::Runtime::InteropServices;

namespace eduLibsodium
{
	public ref class BLAKE2b : Security::Cryptography::HashAlgorithm
	{
	public:
		BLAKE2b(int outlen_bits)
		{
			// Create hash.
			m_state = (crypto_generichash_blake2b_state*)_aligned_malloc(sizeof crypto_generichash_blake2b_state, 64);
			m_outlen = outlen_bits >> 3;

			// Initialize hash.
			crypto_generichash_blake2b_init(m_state, NULL, 0, m_outlen);
		}

		~BLAKE2b()
		{
			BLAKE2b::!BLAKE2b();
		}

	protected:
		!BLAKE2b()
		{
			_aligned_free(m_state);
		}

	public:
		virtual void Initialize() override
		{
			// Initialize hash.
			crypto_generichash_blake2b_init(m_state, NULL, 0, m_outlen);
		}

	protected:
		virtual void HashCore(array<unsigned char> ^data, int start, int size) override
		{
			// Extract, hash, delete.
			unsigned char *buffer = new unsigned char[size];
			#pragma warning(suppress: 6001)
			Marshal::Copy(data, start, IntPtr(buffer), size);
			crypto_generichash_blake2b_update(m_state, buffer, size);
			delete[] buffer;
		}

		virtual array<unsigned char>^ HashFinal() override
		{
			// Finalize and get hash value.
			unsigned char *buffer = new unsigned char[m_outlen];
			crypto_generichash_blake2b_final(m_state, buffer, m_outlen);

			// Marshal to managed.
			array<unsigned char>^ result = gcnew array<unsigned char>(m_outlen);
			Marshal::Copy(IntPtr(buffer), result, 0, m_outlen);
			delete[] buffer;
			return result;
		}

	protected:
		crypto_generichash_blake2b_state* m_state;
		int m_outlen;
	};
}
