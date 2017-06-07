// eduEd25519.h

#pragma once

#include <sodium/crypto_hash_sha512.h>

using namespace System;
using namespace System::Runtime::InteropServices;

namespace eduEd25519 {

	public ref class SHA512 : public System::Security::Cryptography::HashAlgorithm
	{
	public:
		SHA512()
		{
			m_state = new crypto_hash_sha512_state;
		}

		~SHA512()
		{
			delete m_state;
		}

		virtual void Initialize() override
		{
			// Initialize hash.
			crypto_hash_sha512_init(m_state);
		}

		virtual void HashCore(cli::array<unsigned char, 1> ^data, int start, int size) override
		{
			// Extract, hash, delete.
			unsigned char *buffer = new unsigned char[size];
			Marshal::Copy(data, start, IntPtr(buffer), size);
			crypto_hash_sha512_update(m_state, buffer, size);
			delete[] buffer;
		}

		virtual cli::array<unsigned char, 1>^ HashFinal() override
		{
			// Finalize and get hash value.
			unsigned char buffer[crypto_hash_sha512_BYTES];
			crypto_hash_sha512_final(m_state, buffer);

			// Marshal to managed.
			cli::array<unsigned char, 1>^ result = gcnew cli::array<unsigned char, 1>(crypto_hash_sha512_BYTES);
			Marshal::Copy(IntPtr(buffer), result, 0, crypto_hash_sha512_BYTES);
			return result;
		}

	protected:
		crypto_hash_sha512_state* m_state;
	};
}
