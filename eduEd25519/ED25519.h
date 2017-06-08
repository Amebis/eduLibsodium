/*
eduEd25519 - High-speed high-security signatures

Copyright: 2017, The Commons Conservancy eduVPN Programme
SPDX-License-Identifier: GPL-3.0+
*/

#pragma once

#include <sodium/crypto_sign_ed25519.h>
#include <sodium/utils.h>

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

		array<unsigned char>^ SignCombined(array<unsigned char>^ data)
		{
			// Extract data.
			int mlen = data->Length;
			unsigned char *m = new unsigned char[mlen];
#pragma warning(suppress: 6001)
			Marshal::Copy(data, 0, IntPtr(m), mlen);

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

		bool VerifyCombined(array<unsigned char>^ smsg, array<unsigned char>^% data)
		{
			// Extract signed message.
			int smlen = smsg->Length;
			unsigned char *sm = new unsigned char[smlen];
#pragma warning(suppress: 6001)
			Marshal::Copy(smsg, 0, IntPtr(sm), smlen);

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

		array<unsigned char>^ SignDetached(array<unsigned char>^ data)
		{
			// Extract data.
			int mlen = data->Length;
			unsigned char *m = new unsigned char[mlen];
#pragma warning(suppress: 6001)
			Marshal::Copy(data, 0, IntPtr(m), mlen);

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

		bool VerifyDetached(array<unsigned char>^ data, array<unsigned char>^ signature)
		{
			// Extract data.
			int mlen = data->Length;
			unsigned char *m = new unsigned char[mlen];
#pragma warning(suppress: 6001)
			Marshal::Copy(data, 0, IntPtr(m), mlen);

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

	public:
		unsigned char* m_sk;
	};
}
