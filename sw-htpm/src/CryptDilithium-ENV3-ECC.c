#include "Tpm.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "./ecc/ecc_keygen.h"
#include "./ecc/ecc_sign.h"
#include "./ecc/ecc_verify.h"
#include "./ecc/ecc_utils.h"
#include "./commom/cpucycles.h"

// Estrutura para armazenar os parâmetros
typedef struct {
    int ecc_nid;
    const char *curve_name;
} Params;

// Nomes das curvas
const char *curve_names[] = {"secp256k1", "secp384r1", "secp521r1", "ed25519", "ed448"};


void generate_params(uint8_t tpm_dilithium_mode, Params *params) {
    params->ecc_nid = 0;
    params->curve_name = NULL;

    switch (tpm_dilithium_mode) {
        case TPM_DILITHIUM_MODE_4: // p256
            params->ecc_nid = NID_secp256k1;
            params->curve_name = curve_names[0];
            break;
        case TPM_DILITHIUM_MODE_5: // ed25519
			params->ecc_nid = NID_ED25519;
			params->curve_name = curve_names[3]; // ed25519
			break;
		case TPM_DILITHIUM_MODE_6: // p384
			params->ecc_nid = NID_secp384r1;
			params->curve_name = curve_names[1]; // secp384r1
			break;
		case TPM_DILITHIUM_MODE_7: // p521
			params->ecc_nid = NID_secp521r1;
			params->curve_name = curve_names[2]; // secp521r1
			break;
		case TPM_DILITHIUM_MODE_8: // ed448
			params->ecc_nid = NID_ED448;
			params->curve_name = curve_names[4]; // ed448
			break;
        default:
            fprintf(stderr, "Modo de TPM_DILITHIUM inválido para ECC.\n");
            exit(EXIT_FAILURE);
    }
}

LIB_EXPORT TPM_RC
CryptDilithiumSign(
    TPMT_SIGNATURE *sigOut,
    OBJECT *key,                // IN: Key to use
    TPM2B_DIGEST *hIn           // IN: The digest to sign
) {
    TPM_RC retVal = TPM_RC_SUCCESS;

    // Initialize parameters
    Params params;
    generate_params(key->publicArea.parameters.dilithiumDetail.mode, &params);

    size_t ecc_sig_len = 0;
    size_t ecc_sk_size = (size_t)(key->sensitive.sensitive.dilithium.t.size); // Only ECC secret key size

    // Cycle counting for performance
    uint64_t start_cycles=0, end_cycles=0, total_cycles=0;
    uint64_t cpu_overhead = cpucycles_overhead();

    // Parameter checks
    pAssert(sigOut != NULL && key != NULL && hIn != NULL);

    // Set mode used in signature
    sigOut->signature.dilithium.mode = key->publicArea.parameters.dilithiumDetail.mode;

    // Validate signature algorithm
    if (sigOut->sigAlg != ALG_DILITHIUM_VALUE) { // Assuming Dilithium here is a placeholder for ECC signature now
        if (sigOut->sigAlg == ALG_NULL_VALUE) {
            sigOut->signature.dilithium.sig.t.size = 0;
            return TPM_RC_SUCCESS;
        }
        return TPM_RC_SUCCESS;
    }

    // Check valid ECC mode (Modes 4-8 are now purely ECC)
    if (sigOut->signature.dilithium.mode < TPM_DILITHIUM_MODE_4 ||
        sigOut->signature.dilithium.mode > TPM_DILITHIUM_MODE_8) {
        return TPM_RC_VALUE;
    }

    if (params.ecc_nid != 0) {
        EVP_PKEY *ev_privKey = NULL;
        unsigned char *ecc_sig = NULL;
        // Deserialize private key based on curve type
        if (params.ecc_nid != NID_ED25519 && params.ecc_nid != NID_ED448) {
            ev_privKey = get_deserialize_private_key(
                key->sensitive.sensitive.dilithium.t.buffer,
                ecc_sk_size,
                params.curve_name
            );
        } else {
            ev_privKey = EVP_PKEY_new_raw_private_key(
                params.ecc_nid, NULL,
                key->sensitive.sensitive.dilithium.t.buffer,
                ecc_sk_size
            );
        }

        if (!ev_privKey) {
            fprintf(stderr, "Error deserializing the private key %s.\n", params.curve_name);
            return TPM_RC_FAILURE;
        }

        // Sign the message
        // Start CPU cycle measurement
        start_cycles = cpucycles();
        if (!sign_message(ev_privKey, hIn->t.buffer, (size_t)hIn->t.size, &ecc_sig, &ecc_sig_len)) {
            fprintf(stderr, "Error signing message with %s.\n", params.curve_name);
            EVP_PKEY_free(ev_privKey);
            return TPM_RC_FAILURE;
        }
        end_cycles = cpucycles();
        total_cycles = end_cycles - start_cycles - cpu_overhead;



        // Copy signature to output buffer
        memcpy(sigOut->signature.dilithium.sig.t.buffer, ecc_sig, ecc_sig_len);

        // Free resources
        EVP_PKEY_free(ev_privKey);
        free(ecc_sig);
    }

    printf("Total CPU cycles for Sign Mode %d: %llu\n",
    		key->publicArea.parameters.dilithiumDetail.mode,
    		(unsigned long long)total_cycles);

    // Set total signature size in the output structure
    sigOut->signature.dilithium.sig.t.size = ecc_sig_len;

    return retVal;
}



LIB_EXPORT TPM_RC
CryptDilithiumValidateSignature(
    TPMT_SIGNATURE  *sig,           // IN: signature
    OBJECT          *key,           // IN: public ECC key
    TPM2B_DIGEST    *digest         // IN: The digest being validated
)
{
    EVP_PKEY* ev_pubKey = NULL;
    Params params;
    generate_params(key->publicArea.parameters.dilithiumDetail.mode, &params);

    // Cycle counting for performance
    uint64_t start_cycles=0, end_cycles=0, total_cycles=0;
    uint64_t cpu_overhead = cpucycles_overhead();


    size_t ecc_pk_size = (size_t)(key->publicArea.unique.dilithium.t.size); // Only ECC public key size
    unsigned char* ecc_pk = (unsigned char*)malloc(ecc_pk_size * sizeof(unsigned char));
    size_t ecc_sig_len = (size_t)(sig->signature.dilithium.sig.t.size); // Only ECC signature size


    pAssert(sig != NULL && key != NULL && digest != NULL);

    if (sig->signature.dilithium.mode != key->publicArea.parameters.dilithiumDetail.mode) {
        return TPM_RC_SIGNATURE;
    }

    if (sig->sigAlg != ALG_DILITHIUM_VALUE) { // Assuming Dilithium here is a placeholder for ECC signature now
        return TPM_RC_SCHEME;
    }

    // Check valid ECC mode (Modes 4-8 are now purely ECC)
    if (sig->signature.dilithium.mode < TPM_DILITHIUM_MODE_4 || sig->signature.dilithium.mode > TPM_DILITHIUM_MODE_8) {
        return TPM_RC_VALUE;
    }

    if (params.ecc_nid != 0) {

		// Copy pk1 from key
		memcpy(ecc_pk, key->publicArea.unique.dilithium.b.buffer, ecc_pk_size);

		if (params.ecc_nid != NID_ED25519 && params.ecc_nid != NID_ED448) {
			ev_pubKey = get_deserialize_public_key(ecc_pk, ecc_pk_size, params.curve_name);
		} else {
			ev_pubKey = EVP_PKEY_new_raw_public_key(params.ecc_nid, NULL, ecc_pk, ecc_pk_size);
		}

		if (!ev_pubKey) {
			fprintf(stderr, "Erro ao desserializar a chave pública %s.\n", params.curve_name);
			free(ecc_pk);
			return TPM_RC_VALUE;
		}

		start_cycles = cpucycles();

		if (!verify_signature(ev_pubKey, digest->t.buffer,
    	        (size_t)digest->t.size,
				sig->signature.dilithium.sig.t.buffer,
				ecc_sig_len)) {
			EVP_PKEY_free(ev_pubKey);
			free(ecc_pk);
			return TPM_RC_SIGNATURE;
		}
		end_cycles = cpucycles();
		total_cycles = end_cycles - start_cycles - cpu_overhead;

		EVP_PKEY_free(ev_pubKey);
    }

    printf("Total CPU cycles for Verify Mode %d: %llu\n", sig->signature.dilithium.mode, (unsigned long long)total_cycles);

    free(ecc_pk);

    return TPM_RC_SUCCESS;
}


LIB_EXPORT TPM_RC
CryptDilithiumGenerateKey(
    OBJECT *dilithiumKey,   // IN/OUT: Estrutura do objeto onde a chave será criada
    RAND_STATE *rand        // IN: Estado RNG determinístico (se não NULL)
)
{
    TPMT_PUBLIC *publicArea = &dilithiumKey->publicArea;
    TPMT_SENSITIVE *sensitive = &dilithiumKey->sensitive;
    TPM_RC retVal = TPM_RC_NO_RESULT;

    Params params;
    generate_params(dilithiumKey->publicArea.parameters.dilithiumDetail.mode, &params);

    // Cycle counting for performance
    uint64_t start_cycles=0, end_cycles=0, total_cycles=0;
    uint64_t cpu_overhead = cpucycles_overhead();


    size_t pk_len = 0, sk_len = 0;

    pAssert(dilithiumKey != NULL);

     // Certifica-se que Dilithium é usado para assinatura
     if (!IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
         ERROR_RETURN(TPM_RC_NO_RESULT);

    // Gera chave ECC se aplicável
    if (params.ecc_nid != 0) {
    	EVP_PKEY *ev_key = NULL;

	    start_cycles = cpucycles();

        ev_key = generate_key(params.ecc_nid);

        end_cycles = cpucycles();
        total_cycles = end_cycles - start_cycles - cpu_overhead;

        unsigned char *pk = NULL;
        unsigned char *sk = NULL;
        if (!ev_key) {
            fprintf(stderr, "Erro ao gerar chave para NID %d.\n", params.ecc_nid);
            return TPM_RC_FAILURE;
        }

        // Define os tamanhos para serialização
        if (params.ecc_nid == NID_ED25519 || params.ecc_nid == NID_ED448) {
            pk_len = sk_len = (params.ecc_nid == NID_ED448) ? 57 : 32;
            pk = (unsigned char *)malloc(pk_len);
            sk = (unsigned char *)malloc(sk_len);


            if (!pk || !sk ||
                EVP_PKEY_get_raw_public_key(ev_key, pk, &pk_len) <= 0 ||
                EVP_PKEY_get_raw_private_key(ev_key, sk, &sk_len) <= 0) {
                fprintf(stderr, "Erro ao obter chaves raw.\n");
                ERR_print_errors_fp(stderr);
                EVP_PKEY_free(ev_key);
                free(pk);
                free(sk);
                return TPM_RC_FAILURE;
            }
        } else {
            pk = get_serialized_public_key(ev_key, &pk_len);
            sk = get_serialized_private_key(ev_key, &sk_len);
            if (!pk || !sk) {
                fprintf(stderr, "Erro ao serializar chaves.\n");
                EVP_PKEY_free(ev_key);
                free(pk);
                free(sk);
                return TPM_RC_FAILURE;
            }
        }

        // Libera a estrutura ev_key, pois não será mais usada
        EVP_PKEY_free(ev_key);

        memcpy(publicArea->unique.dilithium.t.buffer, pk, pk_len);
        free(pk);
        memcpy(sensitive->sensitive.dilithium.t.buffer, sk, sk_len);
        free(sk);
    }

    printf("Total CPU cycles for GenKey Mode %d: %llu\n",
    		dilithiumKey->publicArea.parameters.dilithiumDetail.mode,
			(unsigned long long)total_cycles);

    publicArea->unique.dilithium.t.size = pk_len;
    sensitive->sensitive.dilithium.t.size = sk_len;
    retVal = TPM_RC_SUCCESS;

Exit:
    return retVal;
}


void generate_params(uint8_t tpm_dilithium_mode, Params *params);
