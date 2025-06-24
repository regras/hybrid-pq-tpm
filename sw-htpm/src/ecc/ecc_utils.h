/*
 * ecc_utils.h
 *
 *  Created on: Oct 23, 2024
 *      Author: rampz
 */

#ifndef ECC_UTILS_H_
#define ECC_UTILS_H_

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/core.h>
#include <openssl/params.h>
#include <openssl/param_build.h>


// Função para imprimir um buffer em formato hexadecimal
void print_buffer(const uint8_t* buffer, size_t length);

// Funções de serialização
unsigned char* get_serialized_public_key(EVP_PKEY* keyPair, size_t* keyLen);
unsigned char* get_serialized_private_key(EVP_PKEY* keyPair, size_t* keyLen);

// Funções de desserialização
EVP_PKEY* get_deserialize_public_key(unsigned char* serializedPublicKey, size_t serializedPublicKeyLen, const char* curveName);
EVP_PKEY* get_deserialize_private_key(unsigned char* serializedPrivateKey, size_t keyLen, const char* curveName);


#endif /* ECC_UTILS_H_ */
