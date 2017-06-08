#
#   eduEd25519 - High-speed high-security signatures
#
#   Copyright: 2017, The Commons Conservancy eduVPN Programme
#   SPDX-License-Identifier: GPL-3.0+
#

All ::

Clean ::
	devenv.com "eduEd25519.sln" /clean "Release|Win32"
	devenv.com "eduEd25519.sln" /clean "Debug|Win32"
	devenv.com "eduEd25519.sln" /clean "Release|x64"
	devenv.com "eduEd25519.sln" /clean "Debug|x64"
#	devenv.com "eduEd25519.sln" /clean "Release|AnyCPU"
#	devenv.com "eduEd25519.sln" /clean "Debug|AnyCPU"

All ::
	devenv.com "eduEd25519.sln" /build "Release|Win32"
	devenv.com "eduEd25519.sln" /build "Debug|Win32"
	devenv.com "eduEd25519.sln" /build "Release|x64"
	devenv.com "eduEd25519.sln" /build "Debug|x64"
#	devenv.com "eduEd25519.sln" /build "Release|AnyCPU"
#	devenv.com "eduEd25519.sln" /build "Debug|AnyCPU"
