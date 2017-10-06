## Using pre-compiled libsodium

1. Download [libsodium pre-compiled MSVC binaries](https://download.libsodium.org/libsodium/releases/) and extract them to `C:\SDK\libsodium\1.0.14`, or any other folder of your choice. `sodium.h` include file should be at `C:\SDK\libsodium\1.0.14\include\sodium.h`.
2. Set environment variable `LIBSODIUM` to `C:\SDK\libsodium\1.0.14\`. Mind the trailing slash.


## Compiling libsodium

1. Clone `git@github.com:Amebis/libsodium.git` to `C:\SDK\libsodium\1.0.14`, or any other folder of your choice.
2. Set environment variable `LIBSODIUM` to `C:\SDK\libsodium\1.0.14\`. Mind the trailing slash.
3. Open `C:\SDK\libsodium\1.0.14\builds\msvc\vs2017\libsodium.sln` using Visual Studio 2017.
4. Select _Build_ >> _Batch Build..._, then click _Select All_ and _Build_.
