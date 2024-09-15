/*
 * Hybrid Post Quantum Cryptography Library
 *
 * ==========================(LICENSE BEGIN)============================
 
The MIT License

Copyright (c) 2023 Doge Protocol Community

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

 * ===========================(LICENSE END)=============================
 * 
 * WARNING! This is an experimental cryptography library. It is not ready for use yet in any production systems!!
 * 
 * 
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "hybrid.h"
#include "hybrid-common.h"
#include "../dilithium/fips202.h"
#include "../dilithium/sign.h"
#include "tweetnacl.h"
#include "../dilithium/randombytes.h"

/*
Secret Key Length = 64 + 2560 + 1312 + 128 = 4064
==================================================
Layout of secret key:

64 bytes                             2560 bytes             1312 bytes             128 bytes
ed25519 secret key with public key | dilithium secret key | dilithium public key | sphincs secret key with public key

The following signature length includes implementation output, in addition to actual algorithm output.

Layout of ED25519 signature
============================

64 bytes          | {1 to 64 bytes}
ed25519 Signature | Message

Layout of Dilithium signature
==============================
2420 bytes
dilithium signature

Layout of Sphincs signature
==============================
49856 bytes
dilithium signature

Layout of Public Key
==============================
32 bytes           | 1312 bytes            | 64 bytes
ed25519 public key | dilithium public key  | sphincs public key


Compact Signature
==================
==================
The compact signature scheme does not sign the message using sphincs+, but only using ed25519 and dilithium. During any emergency event, such as if both ed25519 and dilithium are broken or potential attacks found,
the SPHINCS+ key can be used to prove authenticity of signatures signed earlier or enabled for newer signatures with the same key pair.

In the compact signature mode, a new message digest is created from the original message digest and then hashed using sha3-512. This new message is signed by ed25519 and dilithium

Hybrid Signature Message (compact mode)
=========================================

40 bytes      | {0 to 64 bytes}  | 64 bytes
random nonce  | original message | sphincs public key

hybrid-message-hash = SHA3-512(compact-mode-message)

Hybrid Signature Length (compact mode) = 1 + 1 + 64 + {1 to 64} + 2420 + 64 + 40
=======================================================================================================================
Layout of signature:

1 byte                  | 1 byte            | 64 bytes          | 2420 bytres         | 40 bytes     | {1 to 64 bytes}
signature id (always 1) | length of message | ed25519 signature | dilithium signature | random nonce | original message

Full Signature
==================
==================

Hybrid Signature Length (full, used during breakglass) = 1 + 1 + 64 + {1 to 64} + 2420 + 49856
=======================================================================================================================
Layout of signature:

1 byte                  | 1 byte            | 64 bytes          | {1 to 64 bytes}   | 2420 bytes          | 49856
signature id (always 1) | length of message | ed25519 signature | original message  | dilithium signature | sphincs signature

Message is variable length, between 1 to 64 bytes
*/

int crypto_sign_dilithium_ed25519_keypair(
		unsigned char* pk,
		unsigned char* sk) {

	if (pk == NULL || sk == NULL) {
		return -1;
	}

	unsigned char pk1[32] = { 0 }; //CRYPTO_ED25519_PUBLICKEY_BYTES
	unsigned char sk1[64] = { 0 }; //CRYPTO_ED25519_SECRETKEY_BYTES
	unsigned char pk2[1312] = { 0 }; //CRYPTO_DILITHIUM_PUBLICKEY_BYTES
	unsigned char sk2[2560] = { 0 }; //CRYPTO_DILITHIUM_SECRETKEY_BYTES
	unsigned char seed[32];

//	if (randombytes(seed, sizeof seed) != 0) {
//		return -1;
//	}

	int r1 = crypto_sign_ed25519_keypair_seed(pk1, sk1, seed);
	if (r1 != 0) {
		return -2;
	}

	for (int i = 0; i < CRYPTO_ED25519_PUBLICKEY_BYTES; i++) {
		pk[i] = pk1[i];
	}

	for (int i = 0; i < CRYPTO_ED25519_SECRETKEY_BYTES; i++) { //secret key includes public key
		sk[i] = sk1[i];
	}

	int r2 = mldsa_crypto_sign_keypair(pk2, sk2);

	if (r2 != 0) {
		return -3;
	}

	for (int i = 0; i < CRYPTO_DILITHIUM_SECRETKEY_BYTES; i++) {
		sk[CRYPTO_ED25519_SECRETKEY_BYTES + i] = sk2[i];
	}

	for (int i = 0; i < CRYPTO_DILITHIUM_PUBLICKEY_BYTES; i++) {
		pk[CRYPTO_ED25519_PUBLICKEY_BYTES + i] = pk2[i];
	}
	printf("\n Key pair ");
	return 0;
}

//int crypto_sign_dilithium_ed25519_keypair(unsigned char* pk, unsigned char* sk) {
//	if (pk == NULL || sk == NULL) {
//		return -1;
//	}
//
//	unsigned char seed[32];
//	if (randombytes(seed, sizeof seed) != 0) {
//		return -1;
//	}
//	return crypto_sign_dilithium_ed25519_keypair_seed(pk, sk, seed);
//}

int crypto_sign_dilithium_ed25519(
		unsigned char* sm,
		unsigned long long* smlen,
		const unsigned char* m,
		unsigned long long mlen,
		const unsigned char* sk) {

	if (sm == NULL || smlen == NULL || m == NULL || mlen <= 0 || mlen > MAX_MSG_LEN || sk == NULL) {
		return -1;
	}

	unsigned long long sigLen1 = 0;
	unsigned long sigLen2 = 0;

	unsigned char sig1[64 + 64] = { 0 }; //CRYPTO_ED25519_SIGNATURE_BYTES + MAX_MSG_LEN
	unsigned char sig2[2420] = { 0 }; //CRYPTO_DILITHIUM_MAX_SIGNATURE_BYTES
	unsigned char sk1[64] = { 0 }; //CRYPTO_ED25519_SECRETKEY_BYTES
	unsigned char sk2[2560] = { 0 }; //CRYPTO_DILITHIUM_SECRETKEY_BYTES

	//Copy sk1 from input
	for (int i = 0;i < CRYPTO_ED25519_SECRETKEY_BYTES;i++) {
		sk1[i] = sk[i];
	}

	//Copy sk2 from input (skip public key part of it)
	for (int i = 0;i < CRYPTO_DILITHIUM_SECRETKEY_BYTES;i++) {
		sk2[i] = sk[CRYPTO_ED25519_SECRETKEY_BYTES + i];
	}

	//Always call both sign operations, instead of exiting early from first on failure, to reduce risk from timing attacks if any
	int r1 = crypto_sign_ed25519(sig1, &sigLen1, m, mlen, sk1);
	int r2 = mldsa_crypto_sign_signature(sig2, &sigLen2, m, mlen, sk2);

	if (r1 != 0) {
		return -2;
	}

	if (r2 != 0) {
		return -3;
	}

	if (sigLen1 != CRYPTO_ED25519_SIGNATURE_BYTES + mlen) {
		return -5;
	}

	if (sigLen2 != CRYPTO_DILITHIUM_SIGNATURE_BYTES) {
		return -6;
	}
	//Set signature id and message length
	sm[0] = (unsigned char)DILITHIUM_ED25519_SPHINCS_FULL_ID;
	sm[1] = (unsigned char)mlen;

	//Copy ed25519 signature (which includes the message), to output	
	for (int i = 0;i < (int)sigLen1;i++) {
		sm[LEN_BYTES + i] = sig1[i];
	}

	//Copy the dilithium signature to the output
	for (int i = 0;i < sigLen2;i++) {
		sm[LEN_BYTES + sigLen1 + i] = sig2[i];
	}


	*smlen = LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_DILITHIUM_SIGNATURE_BYTES + mlen;
	printf("\n Sign");
	return 0;
}

int crypto_sign_dilithium_ed25519_open(
		unsigned char* m,
		unsigned long long* mlen,
		const unsigned char* sm,
		unsigned long long smlen,
		const unsigned char* pk) {

	if (m == NULL || mlen == NULL || sm == NULL || smlen < LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + MIN_MSG_LEN + CRYPTO_DILITHIUM_SIGNATURE_BYTES ||
		smlen > LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + MAX_MSG_LEN + CRYPTO_DILITHIUM_SIGNATURE_BYTES || pk == NULL) {
		return -1;
	}

	int id = (size_t)sm[0];
	if (id != DILITHIUM_ED25519_SPHINCS_FULL_ID) {
		return -2;
	}

	int msgLen = (size_t)sm[1];
	if (msgLen <= 0 || msgLen > MAX_MSG_LEN) {
		return -3;
	}

	if (smlen != LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + msgLen + CRYPTO_DILITHIUM_SIGNATURE_BYTES) {
		return -4;
	}

	int sig1Len = CRYPTO_ED25519_SIGNATURE_BYTES + msgLen;

	unsigned char msgFromSignature1[64 + 64] = { 0 }; //MAX_MSG_LEN + CRYPTO_ED25519_SIGNATURE_BYTES
	unsigned long long msgFromSignatureLen1 = 0;
	unsigned char sig1[64 + 64] = { 0 }; //CRYPTO_ED25519_SIGNATURE_BYTES + MAX_MSG_LEN
	unsigned char sig2[2420] = { 0 }; //CRYPTO_DILITHIUM_SIGNATURE_BYTES
	unsigned char pk1[32] = { 0 }; //CRYPTO_ED25519_PUBLICKEY_BYTES
	unsigned char pk2[1312] = { 0 }; //CRYPTO_DILITHIUM_PUBLICKEY_BYTES

	//Copy Sig1 from source, including message
	for (int i = 0;i < (int)sig1Len;i++) {
		sig1[i] = sm[LEN_BYTES + i];
	}

	//Copy pk1 from source
	for (int i = 0;i < CRYPTO_ED25519_PUBLICKEY_BYTES;i++) {
		pk1[i] = pk[i];
	}

	int r1 = crypto_sign_ed25519_open(msgFromSignature1, &msgFromSignatureLen1, sig1, sig1Len, pk1);
	if (r1 != 0) {
		return -5;
	}

	if ((int) msgFromSignatureLen1 != msgLen) {
		return -6;
	}
	
	//Copy actual Sig2 from source
	for (int i = 0; i < CRYPTO_DILITHIUM_SIGNATURE_BYTES; i++) {
		sig2[i] = sm[LEN_BYTES + CRYPTO_ED25519_SIGNATURE_BYTES + msgLen + i];
	}
	

	//Copy pk2 from source
	for (int i = 0;i < CRYPTO_DILITHIUM_PUBLICKEY_BYTES;i++) {
		pk2[i] = pk[i + CRYPTO_ED25519_PUBLICKEY_BYTES];
	}

	int r2 = mldsa_crypto_sign_verify(sig2, CRYPTO_DILITHIUM_SIGNATURE_BYTES, msgFromSignature1, msgLen, pk2);
	if (r2 != 0) {
		return -7;
	}	

	for (int i = 0; i < msgLen; i++) {
		m[i] = msgFromSignature1[i];
	}

	*mlen = msgLen;
	printf("\n Open");
	return 0;
}

int crypto_verify_dilithium_ed25519(
		const unsigned char* m,
		unsigned long long mlen,
		const unsigned char* sm,
		unsigned long long smlen,
		const unsigned char* pk) {

	if (m == NULL|| mlen <= 0 || mlen > MAX_MSG_LEN || sm == NULL || pk == NULL) { //smlen is checked in crypto_sign_dilithium_ed25519_open
		return -1;
	}
	
	unsigned char msgFromSignature1[64 + 64 + 32] = { 0 }; //MAX_MSG_LEN + CRYPTO_ED25519_SIGNATURE_BYTES + CRYPTO_ED25519_PUBLICKEY_BYTES
	unsigned long long msgFromSignatureLen1 = 0;

	int r = crypto_sign_dilithium_ed25519_open(msgFromSignature1, &msgFromSignatureLen1, sm, smlen, pk);
	if (r != 0) {
		return -2;
	}

	if (msgFromSignatureLen1 != mlen) {
		return -3;
	}

	for (int i = 0;i < (int)msgFromSignatureLen1;i++) {
		if (msgFromSignature1[i] != m[i]) {
			return -4;
		}
	}
	printf("\n Verify");
	return 0;
}

int crypto_verify_dilithium(const unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk) {
	if (m == NULL || mlen <= 0 || mlen > MAX_MSG_LEN || sm == NULL || pk == NULL) {
		return -1;
	}

	int r = mldsa_crypto_sign_verify(sm, smlen, m, mlen, pk);
	if (r != 0) {
		return -2;
	}

	return 0;
}
