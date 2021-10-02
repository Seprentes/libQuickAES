/*
 * Copyright (c) 2021 Özgür Ateş Fırat
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <QuickAES++.hpp>
#include <cstring>

#ifdef ECB_ENABLE
void QuickAES::encryptECB(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size) {
	int loop = 0;
	memcpy(result, data, size);
	while(size) {
		if(size < 16)
			size = 16;
		encryptData(result + loop * 16, key);
		loop++;
		size -= 16;
	}
}
#ifdef DECRYPTION_ENABLE
void QuickAES::decryptECB(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size) {
	int loop = 0;
	memcpy(result, data, size);
	while(size) {
		if(size < 16)
			size = 16;
		decryptData(result + loop * 16, key);
		loop++;
		size -= 16;
	}
}
#endif
#endif
#ifdef CBC_ENABLE
void QuickAES::encryptCBC(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size, unsigned char *iv) {
	int loop = 0;
	memcpy(result, data, size);
	for(int i = 0;i < 16;i++)
		result[i] ^= iv[i];
	while(size) {
		if(size < 16)
			size = 16;
		encryptData(result + loop * 16, key);
		if(size != 16) {
			for(int i = 0;i < 16;i++)
				result[(loop + 1) * 16 + i] ^= result[loop * 16 + i];
		}
		loop++;
		size -= 16;
	}
}
#ifdef DECRYPTION_ENABLE
void QuickAES::decryptCBC(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size, unsigned char *iv) {
	int loop = 0;
	memcpy(result, data, size);
	while(size) {
		if(size < 16)
			size = 16;
		decryptData(result + loop * 16, key);
		if(loop) {
			for(int i = 0;i < 16;i++) {
				result[loop * 16 + i] ^= data[(loop - 1) * 16 + i];
			}
		}
		else {
			for(int i = 0;i < 16;i++)
				result[i] ^= iv[i];
		}
		loop++;
		size -= 16;
	}
}
#endif
#endif
#ifdef OFB_ENABLE
void QuickAES::cryptOFB(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size, unsigned char *iv) {
	int loop = 0;
	unsigned char tmp[16];
	memcpy(tmp, iv, 16);
	memcpy(result, data, size);
	while(size) {
		if(size < 16)
			size = 16;
		encryptData(tmp, key);
		for(int i = 0;i < 16;i++)
			result[loop * 16 + i] ^= tmp[i];
		loop++;
		size -= 16;
	}
}
#endif
#ifdef CTR_ENABLE
void QuickAES::cryptCTR(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size, unsigned char *ic) {
	int loop = 0;
	unsigned char tmp[16];
	unsigned char tmp1;
	memcpy(result, data, size);
	while(size) {
		if(size < 16)
			size = 16;
		memcpy(tmp, ic, 16);
		tmp1 = tmp[15];
		tmp[15] += loop;
		if(tmp1 > tmp[15]) {
			for(int i = 14;i;i--) {
				tmp[i]++;
				if(tmp[i] != 0)
					break;
			}
		}
		encryptData(tmp, key);
		for(int i = 0;i < 16;i++)
			result[loop * 16 + i] ^= tmp[i];
		loop++;
		size -= 16;
	}
}
#endif
#ifdef CFB_ENABLE
void QuickAES::encryptCFB(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size, unsigned char *iv) {
	int loop = 0;
	unsigned char tmp[16];
	memcpy(tmp, iv, 16);
	memcpy(result, data, size);
	while(size) {
		if(size < 16)
			size = 16;
		encryptData(tmp, key);
		for(int i = 0;i < 16;i++) {
			result[loop * 16 + i] ^= tmp[i];
			tmp[i] = result[loop * 16 + i];
		}
		loop++;
		size -= 16;
	}
}
void QuickAES::decryptCFB(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size, unsigned char *iv) {
	int loop = 0;
	unsigned char tmp[16];
	memcpy(tmp, iv, 16);
	memcpy(result, data, size);
	while(size) {
		if(size < 16)
			size = 16;
		encryptData(tmp, key);
		for(int i = 0;i < 16;i++) {
			result[loop * 16 + i] ^= tmp[i];
			tmp[i] = data[loop * 16 + i];
		}
		loop++;
		size -= 16;
	}
}
#endif
#ifdef CFB8_ENABLE
void QuickAES::encryptCFB8(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size, unsigned char *iv) {
	int loop = 0;
	unsigned char tmp[16];
	unsigned char tmp1[16];
	memcpy(tmp1, iv, 16);
	memcpy(result, data, size);
	while(size) {
		memcpy(tmp, tmp1, 16);
		encryptData(tmp, key);
		result[loop] ^= tmp[0];
		for(int i = 0;i < 15;i++)
			tmp1[i] = tmp1[i + 1];
		tmp1[15] = result[loop];
		loop++;
		size -= 1;
	}
}
void QuickAES::decryptCFB8(unsigned char *data, unsigned char *key, unsigned char *result, unsigned int size, unsigned char *iv) {
	int loop = 0;
	unsigned char tmp[16];
	unsigned char tmp1[16];
	memcpy(tmp1, iv, 16);
	memcpy(result, data, size);
	while(size) {
		memcpy(tmp, tmp1, 16);
		encryptData(tmp, key);
		result[loop] ^= tmp[0];
		for(int i = 0;i < 15;i++)
			tmp1[i] = tmp1[i + 1];
		tmp1[15] = data[loop];
		loop++;
		size -= 1;
	}
}
#endif
