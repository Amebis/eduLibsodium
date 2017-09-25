## Downloading libsodium

1. Download [libsodium 1.0.14 pre-compiled MSVC binaries](https://download.libsodium.org/libsodium/releases/libsodium-1.0.14-msvc.zip) and extract them to `C:\SDK\libsodium\1.0.14`. (Or change `LIBSODIUM_SDK` in `eduEd25519\eduEd25519.props` to the folder of your choice.) `sodium.h` include file should be at `C:\SDK\libsodium\1.0.14\include\sodium.h`.


## Compiling libsodium

1. Clone `git@github.com:Amebis/libsodium.git` to `C:\SDK\libsodium\1.0.14` (or change `LIBSODIUM_SDK` in `eduEd25519\eduEd25519.props` to the folder of your choice).
2. Open `C:\SDK\libsodium\1.0.14\builds\msvc\vs2017\libsodium.sln` using Visual Studio 2017.
3. Select _Build_ >> _Batch Build..._, then click _Select All_ and _Build_.
