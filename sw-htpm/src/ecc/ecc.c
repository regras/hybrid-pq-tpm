#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <oqs/sig.h>
#include <oqs/sig_ml_dsa.h>
#include "ecc_keygen.h"
#include "ecc_sign.h"
#include "ecc_verify.h"
#include "ecc_utils.h"

#define MESSAGE "Mensagem para assinar"

int main() {
    const int curves[] = {NID_secp256k1, NID_secp384r1, NID_secp521r1, NID_ED25519, NID_ED448};
    const char* curve_names[] = {"secp256k1", "secp384r1", "secp521r1", "ed25519", "ed448"};

    const unsigned char* message = (unsigned char*)MESSAGE;
    size_t message_len = strlen(MESSAGE);

    EVP_PKEY* ev_key = NULL;
    EVP_PKEY* ev_privKey = NULL;
    EVP_PKEY* ev_pubKey = NULL;

    size_t st_pubKeyLen = 0;
    size_t st_privKeyLen = 0;
    size_t st_edSize = 0;
    unsigned char* uc_pubKey = NULL;
    unsigned char* uc_privKey = NULL;

    for (int i = 0; i < 5; ++i) {
        printf("\n== Testando curva %s ==\n", curve_names[i]);

        // BEGIN KeyGen
        ev_key = generate_key(curves[i]);
        if (!ev_key) {
            fprintf(stderr, "Erro gerando chave para %s.\n", curve_names[i]);
            continue;
        }

        if (curves[i] != NID_ED25519 && curves[i] != NID_ED448) {
            st_pubKeyLen = 0;
            uc_pubKey = get_serialized_public_key(ev_key, &st_pubKeyLen);
            st_privKeyLen = 0;
            uc_privKey = get_serialized_private_key(ev_key, &st_privKeyLen);
            printf("Tamanho chave publica: %i bytes \n", st_pubKeyLen);
            printf("Tamanho chave privada: %i bytes \n", st_privKeyLen);
        }
        else {
            // Para EdDSA (ed25519 e ed448), serialize e desserialize usando o formato raw
            st_edSize = (curves[i] == NID_ED448) ? 57 : 32; // 57 bytes para ed448, 32 para ed25519
            uc_pubKey = (unsigned char*)malloc(st_edSize);
            uc_privKey = (unsigned char*)malloc(st_edSize);

            if (!uc_pubKey || EVP_PKEY_get_raw_public_key(ev_key, uc_pubKey, &st_edSize) <= 0) {
                fprintf(stderr, "Erro ao obter a chave pública.\n");
                ERR_print_errors_fp(stderr);
                EVP_PKEY_free(ev_key);
                continue;
            }

            if (!uc_privKey || EVP_PKEY_get_raw_private_key(ev_key, uc_privKey, &st_edSize) <= 0) {
                fprintf(stderr, "Erro ao obter a chave privada.\n");
                ERR_print_errors_fp(stderr);
                EVP_PKEY_free(ev_key);
                continue;
            }
        }

        // END KeyGen

        // BEGIN SIGN
        unsigned char* signature = NULL;
        size_t signature_len = 0;

        if (curves[i] != NID_ED25519 && curves[i] != NID_ED448) {
            ev_privKey = get_deserialize_private_key(uc_privKey, st_privKeyLen, curve_names[i]);
        }
        else {
            ev_privKey = EVP_PKEY_new_raw_private_key(curves[i], NULL, uc_privKey, st_edSize);
        }

        if (!ev_privKey) {
            fprintf(stderr, "Erro desserializar a chave secreta %s.\n", curve_names[i]);
            EVP_PKEY_free(ev_key);
            OPENSSL_free(uc_pubKey);
            OPENSSL_free(uc_privKey);
            continue;
        }

        if (!sign_message(ev_privKey, message, message_len, &signature, &signature_len)) {
            fprintf(stderr, "Erro assinando mensagem com %s.\n", curve_names[i]);
            EVP_PKEY_free(ev_privKey);
            OPENSSL_free(uc_pubKey);
            OPENSSL_free(uc_privKey);
            continue;
        }

        printf("Tamanho da assinatura: %i bytes \n", signature_len);

        EVP_PKEY_free(ev_privKey);
        OPENSSL_free(uc_privKey);

        printf("Mensagem assinada com sucesso!\n");
        // END SIGN

        // BEGIN VERIFY
        if (curves[i] != NID_ED25519 && curves[i] != NID_ED448) {
            ev_pubKey = get_deserialize_public_key(uc_pubKey, st_pubKeyLen, curve_names[i]);
        }
        else {
            ev_pubKey = EVP_PKEY_new_raw_public_key(curves[i], NULL, uc_pubKey, st_edSize);
        }

        if (!ev_pubKey) {
            fprintf(stderr, "Erro desserializar a chave pública %s.\n", curve_names[i]);
            OPENSSL_free(uc_pubKey);
            continue;
        }

        OPENSSL_free(uc_pubKey);

        if (!verify_signature(ev_pubKey, message, message_len, signature, signature_len)) {
            fprintf(stderr, "Erro verificando assinatura com %s.\n", curve_names[i]);
        }
        else {
            printf("Assinatura válida!\n");
        }
        // END VERIFY

        EVP_PKEY_free(ev_pubKey);
        OPENSSL_free(signature);

        printf("Teste PQC!\n");

        uint8_t public_key[OQS_SIG_ml_dsa_44_length_public_key];
        uint8_t secret_key[OQS_SIG_ml_dsa_44_length_secret_key];

        OQS_STATUS status = OQS_SIG_ml_dsa_44_ipd_keypair(public_key, secret_key);

        if (status == OQS_SUCCESS) {
        	printf("Chave MLDSA gerada com sucesso \n");
        } else {
        	printf("Erro na gen MLDSA \n");
        }

    }

    return 0;
}

