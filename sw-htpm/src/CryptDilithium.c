

#include "Tpm.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/sig.h>
#include <oqs/sig_ml_dsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "./ecc/ecc_keygen.h"
#include "./ecc/ecc_sign.h"
#include "./ecc/ecc_verify.h"
#include "./ecc/ecc_utils.h"
#include "./commom/cpucycles.h"

// Estrutura para armazenar os parâmetros
typedef struct {
    int ecc_pk_size;
    int ecc_sk_size;
    int ecc_sig_size;
    int ecc_nid;
    const char *curve_name;
    int mldsa_level;
    int mldsa_pk_size;
    int mldsa_sk_size;
    int mldsa_sig_size;
} Params;

// Nomes das curvas
const char *curve_names[] = {"secp256k1", "secp384r1", "secp521r1", "ed25519", "ed448"};

void generate_params(uint8_t tpm_dilithium_mode, Params *params) {
    // Inicializa com valores padrão para modo DILITHIUM
    params->ecc_pk_size = 0;
    params->ecc_sk_size = 0;
    params->ecc_sig_size = 0;
    params->ecc_nid = 0;
    params->curve_name = NULL;

    switch (tpm_dilithium_mode) {
        case TPM_DILITHIUM_MODE_1: // mldsa44
        	params->mldsa_level = 1;
            params->mldsa_pk_size = OQS_SIG_ml_dsa_44_ipd_length_public_key;
            params->mldsa_sk_size = OQS_SIG_ml_dsa_44_ipd_length_secret_key;
            params->mldsa_sig_size = OQS_SIG_ml_dsa_44_ipd_length_signature;
            break;
        case TPM_DILITHIUM_MODE_2: // mldsa65
			params->mldsa_level = 2;
			params->mldsa_pk_size = OQS_SIG_ml_dsa_65_ipd_length_public_key;
			params->mldsa_sk_size = OQS_SIG_ml_dsa_65_ipd_length_secret_key;
			params->mldsa_sig_size = OQS_SIG_ml_dsa_65_ipd_length_signature;
			break;
        case TPM_DILITHIUM_MODE_3: // mldsa87
			params->mldsa_level = 3;
			params->mldsa_pk_size = OQS_SIG_ml_dsa_87_ipd_length_public_key;
			params->mldsa_sk_size = OQS_SIG_ml_dsa_87_ipd_length_secret_key;
			params->mldsa_sig_size = OQS_SIG_ml_dsa_87_ipd_length_signature;
			break;
        case TPM_DILITHIUM_MODE_4: // mldsa44 + p256
            params->ecc_pk_size = 33;
            params->ecc_sk_size = 32;
            params->ecc_sig_size = 72;
            params->ecc_nid = NID_secp256k1;
            params->curve_name = curve_names[0];
            params->mldsa_level = 1;
            params->mldsa_pk_size = OQS_SIG_ml_dsa_44_ipd_length_public_key;
            params->mldsa_sk_size = OQS_SIG_ml_dsa_44_ipd_length_secret_key;
            params->mldsa_sig_size = OQS_SIG_ml_dsa_44_ipd_length_signature;
            break;
        case TPM_DILITHIUM_MODE_5: // mldsa44 + ed25519
			params->ecc_pk_size = 32;
			params->ecc_sk_size = 32;
			params->ecc_sig_size = 64;
			params->ecc_nid = NID_ED25519;
			params->mldsa_level = 1;
			params->curve_name = curve_names[3]; // ed25519
			params->mldsa_pk_size = OQS_SIG_ml_dsa_44_ipd_length_public_key;
			params->mldsa_sk_size = OQS_SIG_ml_dsa_44_ipd_length_secret_key;
			params->mldsa_sig_size = OQS_SIG_ml_dsa_44_ipd_length_signature;
			break;
		case TPM_DILITHIUM_MODE_6: // mldsa65 + p384
			params->ecc_pk_size = 49;
			params->ecc_sk_size = 48;
			params->ecc_sig_size = 104;
			params->ecc_nid = NID_secp384r1;
			params->curve_name = curve_names[1]; // secp384r1
			params->mldsa_level = 2;
			params->mldsa_pk_size = OQS_SIG_ml_dsa_65_ipd_length_public_key;
			params->mldsa_sk_size = OQS_SIG_ml_dsa_65_ipd_length_secret_key;
			params->mldsa_sig_size = OQS_SIG_ml_dsa_65_ipd_length_signature;
			break;
		case TPM_DILITHIUM_MODE_7: // mldsa87 + p521
			params->ecc_pk_size = 67;
			params->ecc_sk_size = 66;
			params->ecc_sig_size = 139;
			params->ecc_nid = NID_secp521r1;
			params->curve_name = curve_names[2]; // secp521r1
			params->mldsa_level = 3;
			params->mldsa_pk_size = OQS_SIG_ml_dsa_87_ipd_length_public_key;
			params->mldsa_sk_size = OQS_SIG_ml_dsa_87_ipd_length_secret_key;
			params->mldsa_sig_size = OQS_SIG_ml_dsa_87_ipd_length_signature;
			break;
		case TPM_DILITHIUM_MODE_8: // mldsa87 + ed448
			params->ecc_pk_size = 57;
			params->ecc_sk_size = 57;
			params->ecc_sig_size = 114;
			params->ecc_nid = NID_ED448;
			params->curve_name = curve_names[4]; // ed448
			params->mldsa_level = 3;
			params->mldsa_pk_size = OQS_SIG_ml_dsa_87_ipd_length_public_key;
			params->mldsa_sk_size = OQS_SIG_ml_dsa_87_ipd_length_secret_key;
			params->mldsa_sig_size = OQS_SIG_ml_dsa_87_ipd_length_signature;
			break;
        default:
            fprintf(stderr, "Modo de TPM_DILITHIUM inválido.\n");
            exit(EXIT_FAILURE);
    }
}

BOOL CryptDilithiumInit(void) { return TRUE; }
BOOL CryptDilithiumStartup(void) { return TRUE; }

LIB_EXPORT TPM_RC CryptDilithiumSign(
    TPMT_SIGNATURE *sigOut,
    OBJECT *key,                // IN: Key to use
    TPM2B_DIGEST *hIn           // IN: The digest to sign
) {
    TPM_RC retVal = TPM_RC_SUCCESS;

    // Initialize parameters
    Params params;
    generate_params(key->publicArea.parameters.dilithiumDetail.mode, &params);

    // Signature variables
    unsigned long long sigLen1;
    unsigned long sigLen2;
    unsigned char *sig1 = (unsigned char *)malloc((params.ecc_sig_size + (int)hIn->t.size) * sizeof(unsigned char));
    unsigned char *sk1 = (unsigned char *)malloc(params.ecc_sk_size * sizeof(unsigned char));
    EVP_PKEY *ev_privKey = NULL;

    // Cycle counting for performance
    uint64_t start_cycles, end_cycles, total_cycles;

    // Parameter checks
    pAssert(sigOut != NULL && key != NULL && hIn != NULL);

    // Set mode used in signature
    sigOut->signature.dilithium.mode = key->publicArea.parameters.dilithiumDetail.mode;

    // Validate signature algorithm
    if (sigOut->sigAlg != ALG_DILITHIUM_VALUE) {
        if (sigOut->sigAlg == ALG_NULL_VALUE) {
            sigOut->signature.dilithium.sig.t.size = 0;
            return TPM_RC_SUCCESS;
        }
        return TPM_RC_SUCCESS;
    }

    // Check valid Dilithium mode
    if (sigOut->signature.dilithium.mode < TPM_DILITHIUM_MODE_1 ||
        sigOut->signature.dilithium.mode > TPM_DILITHIUM_MODE_8) {
        return TPM_RC_VALUE;
    }

    // Start CPU cycle measurement
    start_cycles = cpucycles();

    if (params.ecc_nid != 0) {

		// Copy sensitive data to sk1
		for (int i = 0; i < params.ecc_sk_size; i++) {
			sk1[i] = key->sensitive.sensitive.dilithium.t.buffer[i];
		}

		// Deserialize private key based on curve type
		if (params.ecc_nid != NID_ED25519 && params.ecc_nid != NID_ED448) {
			ev_privKey = get_deserialize_private_key(sk1, params.ecc_sk_size, params.curve_name);
		} else {
			ev_privKey = EVP_PKEY_new_raw_private_key(params.ecc_nid, NULL, sk1, params.ecc_sk_size);
		}

		if (!ev_privKey) {
			fprintf(stderr, "Error deserializing the private key %s.\n", params.curve_name);
			free(sig1);
			free(sk1);
			return -1;
		}

		// Sign the message
		if (!sign_message(ev_privKey, hIn->t.buffer, (int)hIn->t.size, &sig1, params.ecc_sig_size)) {
			fprintf(stderr, "Error signing message with %s.\n", params.curve_name);
			EVP_PKEY_free(ev_privKey);
			free(sig1);
			free(sk1);
			return -1;
		}
		printf("Message signed successfully!\n");

		// Copy signature to output buffer
		memcpy(sigOut->signature.dilithium.sig.t.buffer, sig1, params.ecc_sig_size);
		free(sig1);
		free(sk1);
		}

    // Generate the second part of the signature with ML-DSA

    int r2 = 0;
    switch (params.mldsa_level) {
          case 1:
              r2 = OQS_SIG_ml_dsa_44_ipd_sign(
            	        sigOut->signature.dilithium.sig.t.buffer + params.ecc_sig_size,
            	        &sigLen2,
            	        hIn->t.buffer,
            	        (size_t)hIn->t.size,
            	        key->sensitive.sensitive.dilithium.t.buffer + params.ecc_sk_size
            	    );
              break;
          case 2:
              r2 = OQS_SIG_ml_dsa_65_ipd_sign(
            	        sigOut->signature.dilithium.sig.t.buffer + params.ecc_sig_size,
            	        &sigLen2,
            	        hIn->t.buffer,
            	        (size_t)hIn->t.size,
            	        key->sensitive.sensitive.dilithium.t.buffer + params.ecc_sk_size
            	    );
              break;
          case 3:
              r2 = OQS_SIG_ml_dsa_87_ipd_sign(
            	        sigOut->signature.dilithium.sig.t.buffer + params.ecc_sig_size,
            	        &sigLen2,
            	        hIn->t.buffer,
            	        (size_t)hIn->t.size,
            	        key->sensitive.sensitive.dilithium.t.buffer + params.ecc_sk_size
            	    );
              break;
          default:
              fprintf(stderr, "Modo inválido: %d\n", params.mldsa_level);
              return TPM_RC_FAILURE;
      }

    // End CPU cycle measurement
    end_cycles = cpucycles();
    total_cycles = end_cycles - start_cycles - cpucycles_overhead();
    printf("Total CPU cycles for Sign: %llu\n", (unsigned long long)total_cycles);

    if (r2 != 0) {
        return -3;
    }
    // Set total signature size in the output structure
    sigOut->signature.dilithium.sig.t.size = params.ecc_sig_size + params.mldsa_sig_size;

Exit:
    return retVal;
}


LIB_EXPORT TPM_RC
CryptDilithiumValidateSignature(
    TPMT_SIGNATURE  *sig,           // IN: signature
    OBJECT          *key,           // IN: public Dilithium key
    TPM2B_DIGEST    *digest         // IN: The digest being validated
)
{
    TPM_RC retVal = TPM_RC_SUCCESS;
    EVP_PKEY* ev_pubKey = NULL;
    Params params;
    generate_params(key->publicArea.parameters.dilithiumDetail.mode, &params);

    uint64_t start_cycles, end_cycles, total_cycles;
    unsigned char* msgFromSignature1 = (unsigned char*)malloc(96 * sizeof(unsigned char));
    unsigned long long msgFromSignatureLen1 = 0;
    unsigned char* pk1 = (unsigned char*)malloc(params.ecc_pk_size * sizeof(unsigned char));
    unsigned char* pk2 = (unsigned char*)malloc(params.mldsa_pk_size * sizeof(unsigned char));
    int sig1Len = 96;

    if (sig->signature.dilithium.sig.t.size != params.ecc_sig_size + params.mldsa_sig_size) {
        free(msgFromSignature1);
        free(pk1);
        free(pk2);
        return TPM_RC_VALUE;
    }

    pAssert(sig != NULL && key != NULL && digest != NULL);

    if (sig->signature.dilithium.mode != key->publicArea.parameters.dilithiumDetail.mode) {
        return TPM_RC_SIGNATURE;
    }

    if (sig->sigAlg != ALG_DILITHIUM_VALUE) {
        return TPM_RC_SCHEME;
    }

    if (sig->signature.dilithium.mode < TPM_DILITHIUM_MODE_1 || sig->signature.dilithium.mode > TPM_DILITHIUM_MODE_4) {
        return TPM_RC_VALUE;
    }

	start_cycles = cpucycles();

    if (params.ecc_nid != 0) {

		// Copy pk1 from key
		memcpy(pk1, key->publicArea.unique.dilithium.b.buffer, params.ecc_pk_size);

		if (params.ecc_nid != NID_ED25519 && params.ecc_nid != NID_ED448) {
			ev_pubKey = get_deserialize_public_key(pk1, params.ecc_pk_size, params.curve_name);
		} else {
			ev_pubKey = EVP_PKEY_new_raw_public_key(params.ecc_nid, NULL, pk1, params.ecc_pk_size);
		}

		if (!ev_pubKey) {
			fprintf(stderr, "Erro ao desserializar a chave pública %s.\n", params.curve_name);
			free(msgFromSignature1);
			free(pk1);
			free(pk2);
			return TPM_RC_VALUE;
		}

		if (!verify_signature(ev_pubKey, msgFromSignature1, &msgFromSignatureLen1, sig->signature.dilithium.sig.t.buffer, sig1Len)) {
			EVP_PKEY_free(ev_pubKey);
			free(msgFromSignature1);
			free(pk1);
			free(pk2);
			return TPM_RC_SIGNATURE;
		}

		EVP_PKEY_free(ev_pubKey);
		free(msgFromSignature1);

		if (msgFromSignatureLen1 != 32) {
			free(pk1);
			free(pk2);
			return TPM_RC_VALUE;
		}
    }

    // Copy pk2 from key for second verification
    memcpy(pk2, key->publicArea.unique.dilithium.b.buffer + params.ecc_pk_size, params.mldsa_pk_size);

    int r2 = 0;
    switch (params.mldsa_level) {
          case 1:
              r2 = OQS_SIG_ml_dsa_44_ipd_verify(
            	        digest->t.buffer,
            	        (size_t)digest->t.size,
            	        sig->signature.dilithium.sig.t.buffer,
            	        params.mldsa_sig_size,
            	        pk2
            	    );
              break;
          case 2:
              r2 = OQS_SIG_ml_dsa_65_ipd_verify(
            	        digest->t.buffer,
            	        (size_t)digest->t.size,
            	        sig->signature.dilithium.sig.t.buffer,
            	        params.mldsa_sig_size,
            	        pk2
            	    );
              break;
          case 3:
              r2 = OQS_SIG_ml_dsa_87_ipd_verify(
            	        digest->t.buffer,
            	        (size_t)digest->t.size,
            	        sig->signature.dilithium.sig.t.buffer,
            	        params.mldsa_sig_size,
            	        pk2
            	    );
              break;
          default:
              fprintf(stderr, "Modo inválido: %d\n", params.mldsa_level);
              return TPM_RC_FAILURE;
      }

    end_cycles = cpucycles();
    total_cycles = end_cycles - start_cycles - cpucycles_overhead();
    printf("Total CPU cycles for Verify: %llu\n", (unsigned long long)total_cycles);

    free(pk1);
    free(pk2);

    if (r2 != 0) {
        return TPM_RC_SIGNATURE;
    }

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

    EVP_PKEY *ev_key = NULL;
    Params params;
    generate_params(dilithiumKey->publicArea.parameters.dilithiumDetail.mode, &params);

    uint64_t start_cycles, end_cycles, total_cycles;

    unsigned char *pk1 = NULL;
    unsigned char *sk1 = NULL;
    size_t st_pubKeyLen = 0;
    size_t st_privKeyLen = 0;
    size_t st_edSize = 0;

    start_cycles = cpucycles();

    // Gera chave ECC se aplicável
    if (params.ecc_nid != 0) {
        ev_key = generate_key(params.ecc_nid);
        if (!ev_key) {
            fprintf(stderr, "Erro ao gerar chave para NID %d.\n", params.ecc_nid);
            return -1;
        }

        if (params.ecc_nid != NID_ED25519 && params.ecc_nid != NID_ED448) {
            pk1 = get_serialized_public_key(ev_key, &st_pubKeyLen);
            sk1 = get_serialized_private_key(ev_key, &st_privKeyLen);
        } else {
            // Para EdDSA (ed25519 e ed448), serialize usando o formato raw
            st_edSize = (params.ecc_nid == NID_ED448) ? 57 : 32;
            pk1 = (unsigned char*)malloc(st_edSize);
            sk1 = (unsigned char*)malloc(st_edSize);

            if (!pk1 || EVP_PKEY_get_raw_public_key(ev_key, pk1, &st_edSize) <= 0 ||
                !sk1 || EVP_PKEY_get_raw_private_key(ev_key, sk1, &st_edSize) <= 0) {
                fprintf(stderr, "Erro ao obter chaves raw.\n");
                ERR_print_errors_fp(stderr);
                EVP_PKEY_free(ev_key);
                return -2;
            }
        }

        memcpy(publicArea->unique.dilithium.t.buffer, pk1, params.ecc_pk_size);
        memcpy(sensitive->sensitive.dilithium.t.buffer, sk1, params.ecc_sk_size);

        free(pk1);
        free(sk1);
    }

    pAssert(dilithiumKey != NULL);

    // Certifica-se que Dilithium é usado para assinatura
    if (!IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
        ERROR_RETURN(TPM_RC_NO_RESULT);

    int r2 = 0;
    switch (params.mldsa_level) {
          case 1:
              r2 = OQS_SIG_ml_dsa_44_ipd_keypair(
                      publicArea->unique.dilithium.t.buffer + params.ecc_pk_size,
                      sensitive->sensitive.dilithium.t.buffer + params.ecc_sk_size);
              break;
          case 2:
              r2 = OQS_SIG_ml_dsa_65_ipd_keypair(
                      publicArea->unique.dilithium.t.buffer + params.ecc_pk_size,
                      sensitive->sensitive.dilithium.t.buffer + params.ecc_sk_size);
              break;
          case 3:
              r2 = OQS_SIG_ml_dsa_87_ipd_keypair(
                      publicArea->unique.dilithium.t.buffer + params.ecc_pk_size,
                      sensitive->sensitive.dilithium.t.buffer + params.ecc_sk_size);
              break;
          default:
              fprintf(stderr, "Modo inválido: %d\n", params.mldsa_level);
              return TPM_RC_FAILURE;
      }

    end_cycles = cpucycles();
    total_cycles = end_cycles - start_cycles - cpucycles_overhead();
    printf("Total CPU cycles for GenKey: %llu\n", (unsigned long long)total_cycles);


    if (r2 != 0) {
        return -3;
    }

    publicArea->unique.dilithium.t.size = params.ecc_pk_size + params.mldsa_pk_size;
    sensitive->sensitive.dilithium.t.size = params.ecc_sk_size + params.mldsa_sk_size;
    retVal = TPM_RC_SUCCESS;

Exit:
    EVP_PKEY_free(ev_key);
    return retVal;
}


void generate_params(uint8_t tpm_dilithium_mode, Params *params);
