/*
	eduEd25519 - High-speed high-security signatures

	Copyright: 2017, The Commons Conservancy eduVPN Programme
	SPDX-License-Identifier: GPL-3.0+
*/

#pragma once

// When libsodium include files are not found, read the chapter "Compiling/Downloading libsodium" in README.md first.
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/utils.h>
extern "C" {
	int _crypto_sign_ed25519_detached(unsigned char *sig,
		unsigned long long *siglen_p,
		const unsigned char *m,
		unsigned long long mlen,
		const unsigned char *sk, int prehashed);

	int _crypto_sign_ed25519_verify_detached(const unsigned char *sig,
		const unsigned char *m,
		unsigned long long   mlen,
		const unsigned char *pk,
		int prehashed);
}

using namespace System;
using namespace System::Runtime::InteropServices;
using namespace System::Text;
using namespace System::Xml;


namespace eduEd25519
{
	public ref class ED25519 : Security::Cryptography::AsymmetricAlgorithm
	{
	public:
		ED25519()
		{
			// Key sizes are fixed.
			KeySizeValue = crypto_sign_ed25519_SECRETKEYBYTES * 8;
			LegalKeySizesValue = gcnew array<Security::Cryptography::KeySizes^>{gcnew Security::Cryptography::KeySizes(crypto_sign_ed25519_SECRETKEYBYTES * 8, crypto_sign_ed25519_SECRETKEYBYTES * 8, 8)};

			// Allocate secure key.
			m_sk = new unsigned char[crypto_sign_ed25519_SECRETKEYBYTES];

			// Generate random keypair.
			unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
			crypto_sign_ed25519_keypair(pk, m_sk);
		}

		ED25519(array<unsigned char>^ pub_key)
		{
			// Key sizes are fixed.
			KeySizeValue = crypto_sign_ed25519_SECRETKEYBYTES * 8;
			LegalKeySizesValue = gcnew array<Security::Cryptography::KeySizes^>{gcnew Security::Cryptography::KeySizes(crypto_sign_ed25519_SECRETKEYBYTES * 8, crypto_sign_ed25519_SECRETKEYBYTES * 8, 8)};

			// Allocate secure key.
			m_sk = new unsigned char[crypto_sign_ed25519_SECRETKEYBYTES];

			// Extract public key.
			Marshal::Copy(pub_key, 0, IntPtr(m_sk + crypto_sign_ed25519_SEEDBYTES), crypto_sign_ed25519_PUBLICKEYBYTES);
		}

		~ED25519()
		{
			ED25519::!ED25519();
		}

	protected:
		!ED25519()
		{
			// Sanitize secret key.
			sodium_memzero(m_sk, crypto_sign_ed25519_SECRETKEYBYTES);
			delete[] m_sk;
		}

	public:
		property String^ SignatureAlgorithm
		{
			virtual String^ get() override
			{
				return "libsodium:ED25519";
			}
		}

		property String^ KeyExchangeAlgorithm
		{
			virtual String^ get() override
			{
				return "RSA-PKCS1-KeyEx";
			}
		}

		virtual void FromXmlString(String ^xmlString) override
		{
			if (xmlString == nullptr)
				throw gcnew ArgumentNullException("xmlString");

			XmlDocument^ document = gcnew XmlDocument();
			document->LoadXml(xmlString);
			XmlNodeList^ nodeList;

			// KeyContainerName is optional.
			nodeList = document->GetElementsByTagName("SecretKey");
			if (nodeList->Count > 0)
			{
				array<unsigned char>^ sk = Convert::FromBase64String(nodeList->Item(0)->InnerText);
				Marshal::Copy(sk, 0, IntPtr(m_sk), crypto_sign_ed25519_SECRETKEYBYTES);
				Array::Clear(sk, 0, crypto_sign_ed25519_SECRETKEYBYTES);
			}
		}

		virtual String^ ToXmlString(bool) override
		{
			StringBuilder^ sb = gcnew StringBuilder();
			sb->Append("<ED25519KeyValue>");

			sb->Append("<SecretKey>");
			array<unsigned char>^ sk = gcnew array<unsigned char>(crypto_sign_ed25519_SECRETKEYBYTES);
			Marshal::Copy(IntPtr(m_sk), sk, 0, crypto_sign_ed25519_SECRETKEYBYTES);
			sb->Append(Convert::ToBase64String(sk));
			sb->Append("</SecretKey>");

			sb->Append("</ED25519KeyValue>");
			return sb->ToString();
		}

		property array<unsigned char>^ PublicKey
		{
			virtual array<unsigned char>^ get()
			{
				array<unsigned char>^ result = gcnew array<unsigned char>(crypto_sign_ed25519_PUBLICKEYBYTES);
				Marshal::Copy(IntPtr(m_sk + crypto_sign_ed25519_SEEDBYTES), result, 0, crypto_sign_ed25519_PUBLICKEYBYTES);
				return result;
			}
		}

		array<unsigned char>^ SignCombined(array<unsigned char>^ data, int start, int mlen)
		{
			// Extract data.
			unsigned char *m = new unsigned char[mlen];
#pragma warning(suppress: 6001)
			Marshal::Copy(data, start, IntPtr(m), mlen);

			// Sign.
			unsigned char *sm = new unsigned char[crypto_sign_ed25519_BYTES + mlen];
			unsigned long long smlen;
			crypto_sign_ed25519(sm, &smlen, m, mlen, m_sk);
			delete[] m;

			// Get signed message.
			array<unsigned char>^ result = gcnew array<unsigned char>((int)smlen);
			Marshal::Copy(IntPtr(sm), result, 0, (int)smlen);
			delete[] sm;
			return result;
		}

		array<unsigned char>^ SignCombined(array<unsigned char>^ data)
		{
			return SignCombined(data, 0, data->Length);
		}

		bool VerifyCombined(array<unsigned char>^ smsg, int start, int smlen, array<unsigned char>^% data)
		{
			// Extract signed message.
			unsigned char *sm = new unsigned char[smlen];
#pragma warning(suppress: 6001)
			Marshal::Copy(smsg, start, IntPtr(sm), smlen);

			// Verify.
			unsigned char *m = new unsigned char[smlen - crypto_sign_ed25519_BYTES];
			unsigned long long mlen;
			bool success = crypto_sign_ed25519_open(m, &mlen, sm, smlen, m_sk + crypto_sign_ed25519_SEEDBYTES) == 0;
			delete[] sm;

			// Get message.
			data = gcnew array<unsigned char>((int)mlen);
			Marshal::Copy(IntPtr(m), data, 0, (int)mlen);
			delete[] m;

			return success;
		}

		bool VerifyCombined(array<unsigned char>^ smsg, array<unsigned char>^% data)
		{
			return VerifyCombined(smsg, 0, smsg->Length, data);
		}

		array<unsigned char>^ SignDetached(array<unsigned char>^ data, int start, int mlen)
		{
			// Extract data.
			unsigned char *m = new unsigned char[mlen];
#pragma warning(suppress: 6001)
			Marshal::Copy(data, start, IntPtr(m), mlen);

			// Sign.
			unsigned char *sig = new unsigned char[crypto_sign_ed25519_BYTES];
			unsigned long long sig_len;
			crypto_sign_ed25519_detached(sig, &sig_len, m, mlen, m_sk);
			delete[] m;

			// Get signature.
			array<unsigned char>^ result = gcnew array<unsigned char>(crypto_sign_ed25519_BYTES);
			Marshal::Copy(IntPtr(sig), result, 0, crypto_sign_ed25519_BYTES);
			delete[] sig;
			return result;
		}

		array<unsigned char>^ SignDetached(array<unsigned char>^ data)
		{
			return SignDetached(data, 0, data->Length);
		}

		bool VerifyDetached(array<unsigned char>^ data, int start, int mlen, array<unsigned char>^ signature)
		{
			// Extract data.
			unsigned char *m = new unsigned char[mlen];
#pragma warning(suppress: 6001)
			Marshal::Copy(data, start, IntPtr(m), mlen);

			// Extract signature.
			unsigned char *sig = new unsigned char[crypto_sign_ed25519_BYTES];
#pragma warning(suppress: 6001)
			Marshal::Copy(signature, 0, IntPtr(sig), crypto_sign_ed25519_BYTES);

			// Verify.
			bool success = crypto_sign_ed25519_verify_detached(sig, m, mlen, m_sk + crypto_sign_ed25519_SEEDBYTES) == 0;
			delete[] sig;
			delete[] m;

			return success;
		}

		bool VerifyDetached(array<unsigned char>^ data, array<unsigned char>^ signature)
		{
			return VerifyDetached(data, 0, data->Length, signature);
		}

		array<unsigned char>^ SignHash(array<unsigned char> ^hash)
		{
			// Extract hash.
			int ph_size = hash->Length;
			unsigned char *ph_buffer = new unsigned char[ph_size];
#pragma warning(suppress: 6001)
			Marshal::Copy(hash, 0, IntPtr(ph_buffer), ph_size);

			// Sign the hash.
			unsigned char sig[crypto_sign_ed25519_BYTES];
			unsigned long long siglen;
			_crypto_sign_ed25519_detached(sig, &siglen, ph_buffer, ph_size, m_sk, 1);
			delete[] ph_buffer;

			// Marshal to managed.
			array<unsigned char>^ result = gcnew array<unsigned char>(crypto_sign_ed25519_BYTES);
			Marshal::Copy(IntPtr(sig), result, 0, crypto_sign_ed25519_BYTES);
			return result;
		}

		bool VerifyHash(array<unsigned char> ^hash, cli::array<unsigned char> ^signature)
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
			bool success = _crypto_sign_ed25519_verify_detached(sig_buffer, ph_buffer, ph_size, m_sk + crypto_sign_ed25519_SEEDBYTES, 1) == 0;
			delete[] sig_buffer;
			delete[] ph_buffer;

			return success;
		}

	private:
		unsigned char* m_sk;
	};

	inline String^ GetResourceString(String^ id)
	{
		auto resourceAssembly = Reflection::Assembly::GetExecutingAssembly();
		auto resourceName = resourceAssembly->GetName()->Name + L".Strings";
		auto resourceManager = gcnew Resources::ResourceManager(resourceName, resourceAssembly);
		return cli::safe_cast<String^>(resourceManager->GetObject(id));
	}
}
