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
    size_t *sig_size = CRYPTO_BYTES;

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

	start_cycles = cpucycles();
	// start = clock();
	retVal = mldsa_crypto_sign_signature(
			sigOut->signature.dilithium.sig.t.buffer,
			sig_size,
			hIn->t.buffer,
			(size_t) hIn->t.size,
			key->sensitive.sensitive.dilithium.t.buffer);

    end_cycles = cpucycles();
    total_cycles = end_cycles - start_cycles - cpucycles_overhead();
    printf("Total CPU cycles for Sign: %llu\n", (unsigned long long)total_cycles);
    // end = clock();
    // cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    // printf("Total CPU cycles for Sign: %f\n", cpu_time_used);

    sigOut->signature.dilithium.sig.t.size = CRYPTO_BYTES;

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

	if(sig->signature.dilithium.sig.b.size < CRYPTO_BYTES)
	  goto badsig;

	start_cycles = cpucycles();
	// start = clock();

	retVal = mldsa_crypto_sign_verify(
			sig->signature.dilithium.sig.t.buffer,
    		(size_t) sig->signature.dilithium.sig.t.size,
			digest->t.buffer,
			(size_t) digest->t.size,
			key->publicArea.unique.dilithium.b.buffer);

	end_cycles = cpucycles();
	total_cycles = end_cycles - start_cycles - cpucycles_overhead();
	printf("Total CPU cycles for Verify: %llu\n", (unsigned long long)total_cycles);
    // end = clock();
    // cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    // printf("Total CPU cycles for Verify: %f\n", cpu_time_used);

	if (retVal != 0) {
		goto badsig;
	}

Exit:
    return retVal;

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

    uint64_t start_cycles, end_cycles, total_cycles;
    // clock_t start, end;
	// double cpu_time_used;

    pAssert(dilithiumKey != NULL);

    // Dilithium is only used for signing
    if (!IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
        ERROR_RETURN(TPM_RC_NO_RESULT);

    start_cycles = cpucycles();
	// start = clock();

    retVal = mldsa_crypto_sign_keypair(
    		publicArea->unique.dilithium.t.buffer,
    		sensitive->sensitive.dilithium.t.buffer);

	end_cycles = cpucycles();
	total_cycles = end_cycles - start_cycles - cpucycles_overhead();
	printf("Total CPU cycles for GenKey: %llu\n", (unsigned long long)total_cycles);
    // end = clock();
    // cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    // printf("Total CPU cycles for GenKey: %f\n", cpu_time_used);

    if (retVal != 0) {
    	return TPM_RC_VALUE;
    }

    publicArea->unique.dilithium.t.size = CRYPTO_PUBLICKEYBYTES;
    sensitive->sensitive.dilithium.t.size = CRYPTO_SECRETKEYBYTES;

    retVal = TPM_RC_SUCCESS;

 Exit:
    return retVal;
}
