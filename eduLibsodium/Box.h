/*
	eduLibsodium - .NET Framework-libsodium bridge

	Copyright: 2022-2024 The Commons Conservancy
	SPDX-License-Identifier: GPL-3.0+
*/

#pragma once

#include <sodium/crypto_box.h>
#include <sodium/utils.h>

using namespace System;
using namespace System::Runtime::InteropServices;
using namespace System::Text;
using namespace System::Xml;


namespace eduLibsodium
{
	public ref class Box : Security::Cryptography::AsymmetricAlgorithm
	{
	public:
		Box()
		{
			// Key sizes are fixed.
			KeySizeValue = crypto_box_SECRETKEYBYTES * 8;
			LegalKeySizesValue = gcnew array<Security::Cryptography::KeySizes^>{gcnew Security::Cryptography::KeySizes(crypto_box_SECRETKEYBYTES * 8, crypto_box_SECRETKEYBYTES * 8, 8)};

			// Allocate keys.
			m_pk = new unsigned char[crypto_box_PUBLICKEYBYTES];
			m_sk = new unsigned char[crypto_box_SECRETKEYBYTES];

			// Generate random keypair.
			crypto_box_keypair(m_pk, m_sk);
		}

		~Box()
		{
			Box::!Box();
		}

	protected:
		!Box()
		{
			// Sanitize secret key.
			sodium_memzero(m_sk, crypto_box_SECRETKEYBYTES);
			delete[] m_sk;
			delete[] m_pk;
		}

	public:
		property String^ SignatureAlgorithm
		{
			virtual String^ get() override
			{
				return "libsodium:Box";
			}
		}

		property String^ KeyExchangeAlgorithm
		{
			virtual String^ get() override
			{
				return "RSA-PKCS1-KeyEx";
			}
		}

		virtual void FromXmlString(String^ xmlString) override
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
				Marshal::Copy(sk, 0, IntPtr(m_sk), crypto_box_SECRETKEYBYTES);
				Array::Clear(sk, 0, crypto_box_SECRETKEYBYTES);
			}
			else
				sodium_memzero(m_sk, crypto_box_SECRETKEYBYTES);

			nodeList = document->GetElementsByTagName("PublicKey");
			if (nodeList->Count > 0)
			{
				array<unsigned char>^ pk = Convert::FromBase64String(nodeList->Item(0)->InnerText);
				Marshal::Copy(pk, 0, IntPtr(m_pk), crypto_box_PUBLICKEYBYTES);
			}
		}

		virtual String^ ToXmlString(bool includePrivateParameters) override
		{
			StringBuilder^ sb = gcnew StringBuilder();
			sb->Append("<BoxKeyValue>");

			if (includePrivateParameters)
			{
				sb->Append("<SecretKey>");
				array<unsigned char>^ sk = gcnew array<unsigned char>(crypto_box_SECRETKEYBYTES);
				Marshal::Copy(IntPtr(m_sk), sk, 0, crypto_box_SECRETKEYBYTES);
				sb->Append(Convert::ToBase64String(sk));
				sb->Append("</SecretKey>");
			}
			sb->Append("<PublicKey>");
			array<unsigned char>^ pk = gcnew array<unsigned char>(crypto_box_PUBLICKEYBYTES);
			Marshal::Copy(IntPtr(m_pk), pk, 0, crypto_box_PUBLICKEYBYTES);
			sb->Append(Convert::ToBase64String(pk));
			sb->Append("</PublicKey>");

			sb->Append("</BoxKeyValue>");
			return sb->ToString();
		}

		property array<unsigned char>^ SecretKey
		{
			virtual array<unsigned char>^ get()
			{
				array<unsigned char>^ result = gcnew array<unsigned char>(crypto_box_SECRETKEYBYTES);
				Marshal::Copy(IntPtr(m_sk), result, 0, crypto_box_SECRETKEYBYTES);
				return result;
			}
		}

		property array<unsigned char>^ PublicKey
		{
			virtual array<unsigned char>^ get()
			{
				array<unsigned char>^ result = gcnew array<unsigned char>(crypto_box_PUBLICKEYBYTES);
				Marshal::Copy(IntPtr(m_pk), result, 0, crypto_box_PUBLICKEYBYTES);
				return result;
			}
		}

	private:
		unsigned char* m_pk;
		unsigned char* m_sk;
	};
}
