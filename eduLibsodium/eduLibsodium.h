/*
    eduLibsodium - .NET Framework-libsodium bridge

    Copyright: 2017 The Commons Conservancy
    SPDX-License-Identifier: GPL-3.0+
*/

#pragma once

using namespace System;

namespace eduLibsodium
{
	inline String^ GetResourceString(String^ id)
	{
		auto resourceAssembly = Reflection::Assembly::GetExecutingAssembly();
		auto resourceName = resourceAssembly->GetName()->Name + L".Strings";
		auto resourceManager = gcnew Resources::ResourceManager(resourceName, resourceAssembly);
		return cli::safe_cast<String^>(resourceManager->GetObject(id));
	}
}
