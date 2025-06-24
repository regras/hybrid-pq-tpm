/*
 * ecc_sign.c
 *
 *  Created on: Oct 23, 2024
 *      Author: rampz
 */

#include "ecc_sign.h"

int sign_message(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
                 unsigned char** sig, size_t* sig_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    if (!mdctx) {
        fprintf(stderr, "Erro criando contexto de assinatura.\n");
        return 0;
    }

    // Inicializa a assinatura de acordo com o tipo de chave
    int pkey_id = EVP_PKEY_id(pkey);
    if (pkey_id == EVP_PKEY_ED25519 || pkey_id == EVP_PKEY_ED448) {
        // Para ED25519 e ED448, inicialize sem especificar algoritmo de hash
        if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) <= 0) {
            fprintf(stderr, "Erro inicializando assinatura para ed25519/ed448.\n");
            EVP_MD_CTX_free(mdctx);
            return 0;
        }
    } else {
        // Para curvas EC tradicionais, use SHA-256
        if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
            fprintf(stderr, "Erro inicializando assinatura para EC.\n");
            EVP_MD_CTX_free(mdctx);
            return 0;
        }
    }

    // Calcula o tamanho da assinatura
    if (EVP_DigestSign(mdctx, NULL, sig_len, msg, msg_len) <= 0) {
        fprintf(stderr, "Erro calculando tamanho da assinatura.\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    // Aloca memória para a assinatura
    *sig = (unsigned char*)malloc(*sig_len);
    if (!*sig) {
        fprintf(stderr, "Erro alocando memória para assinatura.\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    // Gera a assinatura
    if (EVP_DigestSign(mdctx, *sig, sig_len, msg, msg_len) <= 0) {
        fprintf(stderr, "Erro gerando assinatura.\n");
        EVP_MD_CTX_free(mdctx);
        free(*sig);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);
    return 1;
}
