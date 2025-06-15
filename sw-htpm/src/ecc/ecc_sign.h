/*
 * ecc_sign.h
 *
 *  Created on: Oct 23, 2024
 *      Author: rampz
 */

#ifndef ECC_SIGN_H_
#define ECC_SIGN_H_

#include <openssl/evp.h>

// Declaração da função para assinar uma mensagem
int sign_message(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len,
                 unsigned char** sig, size_t* sig_len);

#endif /* ECC_SIGN_H_ */
