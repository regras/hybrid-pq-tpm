/*
 * MIT License
 *
 Copyright (c) 2024 Felipe José Aguiar Rampazzo (FEEC-Unicamp)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "Tpm.h"
#include "./dilithium/params.h"
#include "./dilithium/sign.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "./hybrid/hybrid.h"
#include "./hybrid/hybrid-common.h"
#include "./hybrid/tweetnacl.h"
#include "./dilithium/randombytes.h"

#include "./commom/cpucycles.h"
// #include <time.h>


BOOL CryptDilithiumInit(void) {
    return TRUE;
}

BOOL CryptDilithiumStartup(void) {
    return TRUE;
}

LIB_EXPORT TPM_RC
CryptDilithiumSign(
	     TPMT_SIGNATURE      *sigOut,
	     OBJECT              *key,           // IN: key to use
	     TPM2B_DIGEST        *hIn            // IN: the digest to sign
	     )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;

    unsigned long long sigLen1;
	unsigned long sigLen2;
	unsigned char* sig1 = (unsigned char*)malloc((CRYPTO_ED25519_SIGNATURE_BYTES + (int) hIn->t.size) * sizeof(unsigned char));
	unsigned char* sk1 = (unsigned char*)malloc(CRYPTO_ED25519_SECRETKEY_BYTES * sizeof(unsigned char));

	uint64_t start_cycles, end_cycles, total_cycles;
	// clock_t start, end;
	// double cpu_time_used;


	pAssert(sigOut != NULL && key != NULL && hIn != NULL);

	// Set mode used in signature
	sigOut->signature.dilithium.mode = key->publicArea.parameters.dilithiumDetail.mode;

	TEST(sigOut->sigAlg);
	switch(sigOut->sigAlg)
	{
	  case ALG_NULL_VALUE:
		sigOut->signature.dilithium.sig.t.size = 0;
		return TPM_RC_SUCCESS;
	  case ALG_DILITHIUM_VALUE:
		break;
	  default:
		retVal = TPM_RC_SUCCESS;
		return retVal;
	}

	if (sigOut->signature.dilithium.mode >= TPM_DILITHIUM_MODE_1 &&
			sigOut->signature.dilithium.mode <= TPM_DILITHIUM_MODE_4) {
		retVal = 0;
	} else {
		return TPM_RC_VALUE;
	}

	//Copy sk1 from input
	for (int i = 0;i < CRYPTO_ED25519_SECRETKEY_BYTES;i++) {
		sk1[i] = key->sensitive.sensitive.dilithium.t.buffer[i];
	}

	start_cycles = cpucycles();
	// start = clock();

	int r1 = crypto_sign_ed25519(
		sig1,
		&sigLen1,
		hIn->t.buffer,
		(unsigned long long) hIn->t.size,
		sk1);

	for (int i = 0;i < (int)sigLen1;i++) {
		sigOut->signature.dilithium.sig.t.buffer[i] = sig1[i];
	}
	free(sig1);
	free(sk1);

	int r2 = mldsa_crypto_sign_signature(
		sigOut->signature.dilithium.sig.t.buffer+(sigLen1),
		&sigLen2,
		hIn->t.buffer,
		(size_t) hIn->t.size,
		key->sensitive.sensitive.dilithium.t.buffer+CRYPTO_ED25519_SECRETKEY_BYTES);

    end_cycles = cpucycles();
    total_cycles = end_cycles - start_cycles - cpucycles_overhead();
    printf("Total CPU cycles for Sign: %llu\n", (unsigned long long)total_cycles);
    // end = clock();
    // cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    // printf("Total CPU cycles for Sign: %f\n", cpu_time_used);


	if (r1 != 0) {
		return -2;
	}

	if (r2 != 0) {
		return -3;
	}

	if (sigLen1 != CRYPTO_ED25519_SIGNATURE_BYTES + (unsigned long long) hIn->t.size) {
		return -5;
	}


    sigOut->signature.dilithium.sig.t.size =
    		CRYPTO_ED25519_SIGNATURE_BYTES + hIn->t.size +
    		CRYPTO_DILITHIUM_SIGNATURE_BYTES ;

Exit:
    return retVal;
}

LIB_EXPORT TPM_RC
CryptDilithiumValidateSignature(
			  TPMT_SIGNATURE  *sig,           // IN: signature
			  OBJECT          *key,           // IN: public dilithium key
			  TPM2B_DIGEST    *digest         // IN: The digest being validated
			  )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;

    uint64_t start_cycles, end_cycles, total_cycles;
    // clock_t start, end;
	// double cpu_time_used;

	unsigned char* msgFromSignature1 = (unsigned char*)malloc(96 * sizeof(unsigned char)); //MAX_MSG_LEN + CRYPTO_ED25519_SIGNATURE_BYTES
	unsigned long long msgFromSignatureLen1 = 0;
	unsigned char* pk1 = (unsigned char*)malloc(CRYPTO_ED25519_PUBLICKEY_BYTES * sizeof(unsigned char)); //CRYPTO_ED25519_PUBLICKEY_BYTES
	unsigned char* pk2 = (unsigned char*)malloc(CRYPTO_DILITHIUM_PUBLICKEY_BYTES* sizeof(unsigned char)); //CRYPTO_DILITHIUM_PUBLICKEY_BYTES


	if (sig->signature.dilithium.sig.t.size != CRYPTO_ED25519_SIGNATURE_BYTES +
			digest->t.size +
			CRYPTO_DILITHIUM_SIGNATURE_BYTES)
	{
		return -4;
	}

	int sig1Len = 96;

    pAssert(sig != NULL && key != NULL && digest != NULL);

	// Can't verify signatures with a key of different mode
	if (sig->signature.dilithium.mode != key->publicArea.parameters.dilithiumDetail.mode)
		ERROR_RETURN(TPM_RC_SIGNATURE);

	switch(sig->sigAlg) {
	  case ALG_DILITHIUM_VALUE:
		break;
	  default:
		return TPM_RC_SCHEME;
	}

	TEST(sig->sigAlg);
	if (sig->signature.dilithium.mode >= TPM_DILITHIUM_MODE_1 &&
			sig->signature.dilithium.mode <= TPM_DILITHIUM_MODE_4) {
		retVal=TPM_RC_SUCCESS;
	} else {
		return TPM_RC_SUCCESS + 2;
	}

	//Copy pk1 from source
	for (int i = 0;i < CRYPTO_ED25519_PUBLICKEY_BYTES;i++) {
		pk1[i] = key->publicArea.unique.dilithium.b.buffer[i];
	}

	start_cycles = cpucycles();
	// start = clock();

	int r1 = crypto_sign_ed25519_open(
			msgFromSignature1,
			&msgFromSignatureLen1,
			sig->signature.dilithium.sig.t.buffer,
			sig1Len,
			pk1);

	if (r1 != 0) {
		goto badsig;
	}

	free(pk1);

	if ((int) msgFromSignatureLen1 != 32) {
		return -6;
	}

	free(msgFromSignature1);

	//Copy pk2 from source
	for (int i = 0;i < CRYPTO_DILITHIUM_PUBLICKEY_BYTES;i++) {
		pk2[i] = key->publicArea.unique.dilithium.b.buffer[i + CRYPTO_ED25519_PUBLICKEY_BYTES];
	}

	int r2 = mldsa_crypto_sign_verify(
		sig->signature.dilithium.sig.t.buffer+sig1Len,
		CRYPTO_DILITHIUM_SIGNATURE_BYTES,
		digest->t.buffer,
		(size_t) digest->t.size,
		pk2);

	end_cycles = cpucycles();
	total_cycles = end_cycles - start_cycles - cpucycles_overhead();
	printf("Total CPU cycles for Verify: %llu\n", (unsigned long long)total_cycles);
    // end = clock();
    // cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    // printf("Total CPU cycles for Verify: %f\n", cpu_time_used);

	free(pk2);

	if (r2 != 0) {
		goto badsig;
	}

Exit:
    return TPM_RC_SUCCESS;

    /* Signature verification failed */
    badsig:
    return TPM_RC_SIGNATURE;
}

LIB_EXPORT TPM_RC
CryptDilithiumGenerateKey(
            // IN/OUT: The object structure in which the key is created.
		    OBJECT              *dilithiumKey,
            // IN: if not NULL, the deterministic RNG state
		    RAND_STATE          *rand
		    )
{
    TPMT_PUBLIC         *publicArea = &dilithiumKey->publicArea;
    TPMT_SENSITIVE      *sensitive = &dilithiumKey->sensitive;
    TPM_RC               retVal = TPM_RC_NO_RESULT;

    //Measure CPU -- comment if not needed
    uint64_t start_cycles, end_cycles, total_cycles;
	// clock_t start, end;
	// double cpu_time_used;

    unsigned char* pk1 = (unsigned char*)malloc(CRYPTO_ED25519_PUBLICKEY_BYTES * sizeof(unsigned char)); //CRYPTO_ED25519_PUBLICKEY_BYTES
    unsigned char* sk1 = (unsigned char*)malloc(CRYPTO_ED25519_SECRETKEY_BYTES * sizeof(unsigned char)); //CRYPTO_ED25519_SECRETKEY_BYTES
    unsigned char* seed = (unsigned char*)malloc(32 * sizeof(unsigned char));

 	start_cycles = cpucycles();
 	// start = clock();

 	int r1 = crypto_sign_ed25519_keypair_seed(pk1, sk1, seed);

	if (r1 != 0) {
		return -2;
	}

	for (int i = 0; i < CRYPTO_ED25519_PUBLICKEY_BYTES; i++) {
		publicArea->unique.dilithium.t.buffer[i] = pk1[i];
	}

	for (int i = 0; i < CRYPTO_ED25519_SECRETKEY_BYTES; i++) { //secret key includes public key
		sensitive->sensitive.dilithium.t.buffer[i] = sk1[i];
	}

	free(pk1);
	free(sk1);
	free(seed);

    pAssert(dilithiumKey != NULL);

    // Dilithium is only used for signing
    if (!IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
        ERROR_RETURN(TPM_RC_NO_RESULT);


    int r2 = mldsa_crypto_sign_keypair(
    		publicArea->unique.dilithium.t.buffer+CRYPTO_ED25519_PUBLICKEY_BYTES,
			sensitive->sensitive.dilithium.t.buffer+CRYPTO_ED25519_SECRETKEY_BYTES);

	end_cycles = cpucycles();
	total_cycles = end_cycles - start_cycles - cpucycles_overhead();
	printf("Total CPU cycles for GenKey: %llu\n", (unsigned long long)total_cycles);
    // end = clock();
    // cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    // printf("Total CPU cycles for GenKey: %f\n", cpu_time_used);

    if (r2 != 0) {
    	return -3;
    }

    publicArea->unique.dilithium.t.size = CRYPTO_ED25519_PUBLICKEY_BYTES + CRYPTO_PUBLICKEYBYTES;
    sensitive->sensitive.dilithium.t.size = CRYPTO_ED25519_SECRETKEY_BYTES + CRYPTO_SECRETKEYBYTES;

    retVal = TPM_RC_SUCCESS;

 Exit:
    return retVal;
}
