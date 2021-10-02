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
#ifndef NDEBUG
	#include <cassert>
#endif

#define Mul2(a) ((a & 0x80) ? ((a << 1) ^ 0x11b) : (a << 1))
#define Mul3(a) (Mul2(a) ^ a)

QuickAES::QuickAES(unsigned int size) {
	setKeySize(size);
}
void QuickAES::setKeySize(unsigned int size) {
	switch(size) {
		case 128:
			Nk = 4;
			Nr = 10;
			break;
		case 192:
			Nk = 6;
			Nr = 12;
			break;
		case 256:
			Nk = 8;
			Nr = 14;
			break;
		#ifndef NDEBUG
		all:
			assert((size == 128) | (size == 192) | (size == 256));
		#endif
	}
}
unsigned char QuickAES::Multiply(unsigned char a, unsigned char b) {
	unsigned char tmp = 0;
	for(int i = 0; i < 8; i++) {
		if (b & 1)
			tmp ^= a;
		if (a & 0x80)
			a = (a << 1) ^ 0x11b;
		else
			a <<= 1;
		b >>= 1;
	}
	return tmp;
}
void QuickAES::keyExpansion(unsigned char *key, unsigned char *result, const int expandedKeySize) {
	unsigned char tmp[4];
	unsigned char tmp2;
	for(int i = 0;i < 4 * Nk;i++)
		result[i] = key[i];
	for(int i = Nk;i < expandedKeySize;i++) {
		tmp[0] = result[i * 4 - 4];
		tmp[1] = result[i * 4 - 3];
		tmp[2] = result[i * 4 - 2];
		tmp[3] = result[i * 4 - 1];
		if(i % Nk == 0) {
			tmp2 = tmp[0];
			tmp[0] = rijndaelSbox[tmp[1]] ^ RC[i / Nk];
			tmp[1] = rijndaelSbox[tmp[2]];
			tmp[2] = rijndaelSbox[tmp[3]];
			tmp[3] = rijndaelSbox[tmp2];
		}
		else if((Nk > 6) & ((i % Nk) == 4)) {
			tmp[0] = rijndaelSbox[tmp[0]];
			tmp[1] = rijndaelSbox[tmp[1]];
			tmp[2] = rijndaelSbox[tmp[2]];
			tmp[3] = rijndaelSbox[tmp[3]];
		}
		result[i * 4] = result[(i - Nk) * 4] ^ tmp[0];
		result[i * 4 + 1] = result[(i - Nk) * 4 + 1] ^ tmp[1];
		result[i * 4 + 2] = result[(i - Nk) * 4 + 2] ^ tmp[2];
		result[i * 4 + 3] = result[(i - Nk) * 4 + 3] ^ tmp[3];
	}
}
void QuickAES::addRoundKey(unsigned char *state, unsigned char *key, int loop) {
	unsigned char *pointerKey = key + loop * 16;
	for(int i = 0;i < 16;i++)
		state[i] ^= pointerKey[i];
}
void QuickAES::subBytesShiftRows(unsigned char *state) {
	unsigned char tmp;

	state[0] = rijndaelSbox[state[0]];
	state[4] = rijndaelSbox[state[4]];
	state[8] = rijndaelSbox[state[8]];
	state[12] = rijndaelSbox[state[12]];

	tmp = state[1];
	state[1] = rijndaelSbox[state[5]];
	state[5] = rijndaelSbox[state[9]];
	state[9] = rijndaelSbox[state[13]];
	state[13] = rijndaelSbox[tmp];

	tmp = state[2];
	state[2] = rijndaelSbox[state[10]];
	state[10] = rijndaelSbox[tmp];
	tmp = state[6];
	state[6] = rijndaelSbox[state[14]];
	state[14] = rijndaelSbox[tmp];

	tmp = state[15];
	state[15] = rijndaelSbox[state[11]];
	state[11] = rijndaelSbox[state[7]];
	state[7] = rijndaelSbox[state[3]];
	state[3] = rijndaelSbox[tmp];
}
#ifdef DECRYPTION_ENABLE
void QuickAES::invSubBytesShiftRows(unsigned char *state) {
	unsigned char tmp;

	state[0] = inverseSbox[state[0]];
	state[4] = inverseSbox[state[4]];
	state[8] = inverseSbox[state[8]];
	state[12] = inverseSbox[state[12]];

	tmp = state[13];
	state[13] = inverseSbox[state[9]];
	state[9] = inverseSbox[state[5]];
	state[5] = inverseSbox[state[1]];
	state[1] = inverseSbox[tmp];

	tmp = state[2];
	state[2] = inverseSbox[state[10]];
	state[10] = inverseSbox[tmp];
	tmp = state[6];
	state[6] = inverseSbox[state[14]];
	state[14] = inverseSbox[tmp];

	tmp = state[3];
	state[3] = inverseSbox[state[7]];
	state[7] = inverseSbox[state[11]];
	state[11] = inverseSbox[state[15]];
	state[15] = inverseSbox[tmp];
}
#endif
void QuickAES::mixColumns(unsigned char *state) {
	unsigned char tmp[4];
	for(int i = 0;i < 4;i++) {
		tmp[0] = state[i * 4];
		tmp[1] = state[i * 4 + 1];
		tmp[2] = state[i * 4 + 2];
		tmp[3] = state[i * 4 + 3];
		state[i * 4] = Mul2(tmp[0]) ^ Mul3(tmp[1]) ^ tmp[2] ^ tmp[3];
		state[i * 4 + 1] = tmp[0] ^ Mul2(tmp[1]) ^ Mul3(tmp[2]) ^ tmp[3];
		state[i * 4 + 2] = tmp[0] ^ tmp[1] ^ Mul2(tmp[2]) ^ Mul3(tmp[3]);
		state[i * 4 + 3] = Mul3(tmp[0]) ^ tmp[1] ^ tmp[2] ^ Mul2(tmp[3]);
	}
}
#ifdef DECRYPTION_ENABLE
void QuickAES::invMixColumns(unsigned char *state) {
	unsigned char tmp[4];
	for(int i = 0;i < 4;i++) {
		tmp[0] = state[i * 4];
		tmp[1] = state[i * 4 + 1];
		tmp[2] = state[i * 4 + 2];
		tmp[3] = state[i * 4 + 3];
		state[i * 4] = Multiply(tmp[0], 0x0e) ^ Multiply(tmp[1], 0x0b) ^ Multiply(tmp[2], 0x0d) ^ Multiply(tmp[3], 0x09);
		state[i * 4 + 1] = Multiply(tmp[0], 0x09) ^ Multiply(tmp[1], 0x0e) ^ Multiply(tmp[2], 0x0b) ^ Multiply(tmp[3], 0x0d);
		state[i * 4 + 2] = Multiply(tmp[0], 0x0d) ^ Multiply(tmp[1], 0x09) ^ Multiply(tmp[2], 0x0e) ^ Multiply(tmp[3], 0x0b);
		state[i * 4 + 3] = Multiply(tmp[0], 0x0b) ^ Multiply(tmp[1], 0x0d) ^ Multiply(tmp[2], 0x09) ^ Multiply(tmp[3], 0x0e);
	}
}
#endif
void QuickAES::encryptData(unsigned char *data, unsigned char *key) {
	const int expansionLoopNumber = 4 * (Nr + 1);
	unsigned char *expandedKey = new unsigned char[expansionLoopNumber * 4];
	keyExpansion(key, expandedKey, expansionLoopNumber);
	addRoundKey(data, expandedKey, 0);
	for(int i = 1;i < Nr;i++) {
		subBytesShiftRows(data);
		mixColumns(data);
		addRoundKey(data, expandedKey, i);
	}
	subBytesShiftRows(data);
	addRoundKey(data, expandedKey, Nr);
	delete[] expandedKey;
}
#ifdef DECRYPTION_ENABLE
void QuickAES::decryptData(unsigned char *data, unsigned char *key) {
	const int expansionLoopNumber = 4 * (Nr + 1);
	unsigned char *expandedKey = new unsigned char[expansionLoopNumber * 4];
	keyExpansion(key, expandedKey, expansionLoopNumber);
	addRoundKey(data, expandedKey, Nr);
	for(int i = Nr - 1;i > 0;i--) {
		invSubBytesShiftRows(data);
		addRoundKey(data, expandedKey, i);
		invMixColumns(data);
	}
	invSubBytesShiftRows(data);
	addRoundKey(data, expandedKey, 0);
	delete[] expandedKey;
}
#endif
