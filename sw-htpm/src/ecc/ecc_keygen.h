/*
 * ecc_keygen.h
 *
 *  Created on: Oct 23, 2024
 *      Author: rampz
 */

#ifndef ECC_KEYGEN_H_
#define ECC_KEYGEN_H_

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>

// Declaração da função para gerar uma chave
//EVP_PKEY* generate_key(int nid, unsigned char *pubKey, size_t *lenPubKey, unsigned char *privKey, size_t *lenPrivKey);
EVP_PKEY* generate_key(int nid);

#endif /* ECC_KEYGEN_H_ */
