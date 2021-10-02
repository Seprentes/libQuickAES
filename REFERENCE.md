# libQuickAES++ Tutorial And API reference
_________________________________________

## API Reference
`QucikAES::QuickAES(unsigned int size)`

Initializes library with size key size. Key size must be 128, 192 or 256.

`void QucikAES::setKeySize(unsigned int size)`

Changes key size.

`void QuickAES::encryptData(unsigned char *data, unsigned char *key)`

Encrypts 128 bit data with AES.

`void QuickAES::decryptData(unsigned char *data, unsigned char *key)`

Decrypts 128 bit data with AES.

`void QuickAES::encryptECB(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size)`

Encrpyts data with ECB block cipher mode of operation.

`void QuickAES::encryptECB(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size)`

Decrpyts data with ECB block cipher mode of operation.

`void QucikAES::encryptCBC(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size, unsigned char *iv)`

Encrypts data with CBC block cipher mode of operation.

`void QucikAES::decryptCBC(unsigned char *data, unsigned char key, unsigned char *result, unsigned int size, unsigned char *iv)`

Decrypts data with CBC block cipher mode of operation.

`void QucikAES::cryptOFB(unsigned char \*data, unsigned char \*key, unsigned char \*result, unsigned int size, unsigned char \*iv)`

Encrypts and decrypts data with OFB block cipher mode of operation.

`void QucikAES::cryptCTR(unsigned char \*data, unsigned char \*key, unsigned char \*result, unsigned int size, unsigned char \*ic)`

Encrypts and decrypts data with CTR block cipher mode of operation.

`void QucikAES::encryptCFB(unsigned char \*data, unsigned char \*key, unsigned char \*result, unsigned int size, unsigned char \*iv)`

Encrypts data with 128 bit CFB block cipher mode of operation.

`void QucikAES::decryptCFB(unsigned char \*data, unsigned char \*key, unsigned char \*result, unsigned int size, unsigned char \*iv)`

Decrypts data with 128 bit CFB block cipher mode of operation.

`void QucikAES::encryptCFB8(unsigned char \*data, unsigned char \*key, unsigned char \*result, unsigned int size, unsigned char \*iv)`

Encrypts data with 8 bit CFB block cipher mode of operation.

`void QucikAES::decryptCFB8(unsigned char \*data, unsigned char \*key, unsigned char \*result, unsigned int size, unsigned char \*iv)`

Decrypts data with 128 bit CFB8 block cipher mode of operation.

## Basic 128 bit ECB encryption app

```
#include <QuickAES++.hpp>
#include <iostream>
int main() {
	unsigned char key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	unsigned char data[64] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
	unsigned char result[64];
	QuickAES aes(128);
	aes.encryptECB(data, key, result, 64);
	for(int i = 0;i < 64;i++)
		std::cout << std::hex << static_cast<unsigned int>(result[i]) << ' ';
	std::cout << std::endl;
}
```
