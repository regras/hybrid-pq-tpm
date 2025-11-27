/*
 * verify.c
 *
 *  Created on: Oct 23, 2024
 *      Author: rampz
 */

#include "ecc_verify.h"

int verify_signature(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
                     const unsigned char* sig, size_t sig_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    if (!mdctx) {
        fprintf(stderr, "Erro criando contexto de verificação.\n");
        return 0;
    }

    // Determina o tipo de chave e inicializa a verificação adequadamente
    int pkey_id = EVP_PKEY_id(pkey);
    if (pkey_id == EVP_PKEY_ED25519 || pkey_id == EVP_PKEY_ED448) {
        // Para ED25519 e ED448, inicialize sem especificar algoritmo de hash
        if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) <= 0) {
            fprintf(stderr, "Erro inicializando verificação para ed25519/ed448.\n");
            EVP_MD_CTX_free(mdctx);
            return 0;
        }
    } else {
        // Para curvas EC tradicionais, use SHA-256
        if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
            fprintf(stderr, "Erro inicializando verificação para EC.\n");
            EVP_MD_CTX_free(mdctx);
            return 0;
        }
    }

    int result = EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(mdctx);

    return result;
}
