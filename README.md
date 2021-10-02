# libQuickAES++
_______________

## Statement
libQuickAES++ is a simple, modern and easy to use 128, 192 and 256 bit AES encryption and decryption library supports;

* ECB
* CBC
* OFB
* CTR
* CFB8
* CFB128

block cipher modes of operation.

## Building and installing
### GNU/Linux and FreeBSD
You need to install CMake and a C++ compiler like gcc for building this library. Run following commands for building libQuickAES++

```
git clone https://github.com/lumbricusterrestris/libQuickAES++
cd libQuickAES++
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

For installing libQuickAES++ you need to run following command with root permissions in the build directory:

```
make install
```

### Microsoft Windows
#### With Visual Studio
You need to install Visual Studio with "Desktop Development with C++", "C++ CMake Tools for Windows" and git. First, Open x64 Native Tools Command Promt For Visual Studio XXX with administrator privileges. Then run following commands for building:

```
git clone https://github.com/lumbricusterrestris/libQuickAES++
cd libQucikAES++
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -GNinja ..
ninja
```

For installing run following command:

```
ninja install
```

#### With MSYS2 MinGW
Start MSYS2 MinGW 64 bit. And run following command for installing dependencies of libQucikAES++:
```
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja git
```
Then, run following command for building:

```
git clone https://github.com/lumbricusterrestris/libQuickAES++
cd libQucikAES++
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -GNinja ..
ninja
```

After that, you need to run following command for installing:

```
ninja install
```

## CMake Options

 * `BUILD_STATIC` Build static library. (Default: ON)
 * `BUILD_TESTING` Build test. GTest requied (Default: ON)
 * `INSTALL_CMAKE_FIND` Install CMake find file. (Default: ON)
 * `INSTALL_CMAKE_FIND` Install CMake find file. (Default: ON)
 * `INSTALL_PKGCONFIG_MODULE` Install pkgconfig module. (Default: ON for UNIX OFF for others)
 * `DECRYPTION_ENABLE` Enables or disables decryption. (Default: ON)
 * `ECB_ENABLE` Enables or disables ECB cipher mode of operation. (Default: ON)
 * `CBC_ENABLE` Enables or disables CBC cipher mode of operation. (Default: ON)
 * `OFB_ENABLE` Enables or disables OFB cipher mode of operation. (Default: ON)
 * `CTR_ENABLE` Enables or disables CTR cipher mode of operation. (Default: ON)
 * `CFB8_ENABLE` Enables or disables CFB8 cipher mode of operation. (Default: ON)
 * `CFB_ENABLE` Enables or disables CFB128 cipher mode of operation. (Default: ON)

