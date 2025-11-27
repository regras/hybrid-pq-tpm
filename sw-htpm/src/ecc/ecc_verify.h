/*
 * ecc_verify.h
 *
 *  Created on: Oct 23, 2024
 *      Author: rampz
 */

#ifndef ECC_VERIFY_H_
#define ECC_VERIFY_H_

#include <openssl/evp.h>

// Função para verificar uma assinatura
int verify_signature(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
                     const unsigned char* sig, size_t sig_len);

#endif /* ECC_VERIFY_H_ */
