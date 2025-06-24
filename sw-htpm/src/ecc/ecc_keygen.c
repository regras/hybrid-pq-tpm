/*
 * gen_key.c
 *
 *  Created on: Oct 23, 2024
 *      Author: rampz
 */
//Versão com a API atual (3.0) mas que nao funciona compressão
//vide https://github.com/openssl/openssl/issues/24594
// 0x04 significa que a chave nao está comprimida (coordenada y presente
// 0x02 significa que a coordenada y é par.
// 0x03 significa que a coordenada y é ímpar.

#include "ecc_keygen.h"


EVP_PKEY* generate_key(int nid) {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = NULL;

    if (nid == NID_ED25519) {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    } else if (nid == NID_ED448) {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);
    } else {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    }

    if (!pctx) {
        fprintf(stderr, "Erro criando contexto para chave.\n");
        return NULL;
    }

    if (nid == NID_ED25519 || nid == NID_ED448) {
        if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            fprintf(stderr, "Erro gerando chave ed25519 ou ed448.\n");
            EVP_PKEY_CTX_free(pctx);
            return NULL;
        }
    } else {
        if (EVP_PKEY_keygen_init(pctx) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0 ||
            EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            fprintf(stderr, "Erro gerando chave EC.\n");
            EVP_PKEY_CTX_free(pctx);
            return NULL;
        }
//         Define a compressão para curvas EC tradicionais
         EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
         if (ec_key) {
             EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_COMPRESSED);
             EVP_PKEY_set1_EC_KEY(pkey, ec_key);
             EC_KEY_free(ec_key);
         }
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/*
 * gen_key.c
 *
 *  Created on: Oct 23, 2024
 *      Author: rampz
 */

//#include "ecc_keygen.h"
//
//EVP_PKEY* generate_key(int nid, unsigned char *pubKey, size_t *lenPubKey, unsigned char *privKey, size_t *lenPrivKey) {
//    EVP_PKEY* pkey = NULL;
//    EVP_PKEY_CTX* pctx = NULL;
//
//    if (nid == NID_ED25519) {
//        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
//    } else if (nid == NID_ED448) {
//        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);
//    } else {
//        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
//    }
//
//    if (!pctx) {
//        fprintf(stderr, "Erro criando contexto para chave.\n");
//        return NULL;
//    }
//
//    int result=0;
//
//    if (nid == NID_ED25519 || nid == NID_ED448) {
//        if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0) {
//            fprintf(stderr, "Erro gerando chave EdDSA.\n");
//            EVP_PKEY_CTX_free(pctx);
//            return NULL;
//        }
//        // Obter chaves "raw" para Ed25519 ou Ed448
//        else{
//			if (EVP_PKEY_get_raw_public_key(pkey, pubKey, lenPubKey) <= 0) {
//				fprintf(stderr, "Erro ao obter a chave pública 'raw'.\n");
//				result = -1;
//			}
//			if (EVP_PKEY_get_raw_private_key(pkey, privKey, lenPrivKey) <= 0) {
//				fprintf(stderr, "Erro ao obter a chave privada 'raw'.\n");
//				result = -1;
//			}
//        }
//    //Para curvas NIST (P-256, P-384, P-521)
//    } else {
//        if (EVP_PKEY_keygen_init(pctx) <= 0 ||
//            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0 ||
//            EVP_PKEY_keygen(pctx, &pkey) <= 0) {
//            fprintf(stderr, "Erro gerando chave EC.\n");
//            EVP_PKEY_CTX_free(pctx);
//            return NULL;
//        }
//
//        // Define a compressão para curvas EC tradicionais
//        EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
//        if (ec_key) {
//            EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_COMPRESSED);
//            EVP_PKEY_set1_EC_KEY(pkey, ec_key);
//            EC_KEY_free(ec_key);
//        }
//    	*pubKey = get_serialized_public_key(pkey, &lenPubKey);
//    	*privKey = get_serialized_private_key(pkey, &lenPrivKey);
//    }
//
//    EVP_PKEY_free(pkey);
//
//    EVP_PKEY_CTX_free(pctx);
//    return result;
//}

//int generate_key_serialized(
//		int nid,
//		unsigned char* publicKey,
//		size_t* publicKeyLen,
//		unsigned char* secretKey,
//		size_t* secretKeyLen
//		){
//
//	EVP_PKEY* key = generate_key(nid);
//
//	*publicKeyLen = 0;
//	*publicKey = get_serialized_public_key(key, &publicKeyLen);
//	*secretKeyLen = 0;
//	*secretKey = get_serialized_private_key(key, &secretKeyLen);
//
//	OPENSSL_free(key);
//
//	return 0;
//}
