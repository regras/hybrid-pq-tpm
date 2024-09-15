#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>

// Random functions from TPM
#include "Tpm.h"
#include "CryptRand_fp.h"

void indcpa_keypair(unsigned char *pk,
                   unsigned char *sk, const uint64_t kyber_k,
                   const uint64_t kyber_polyvecbytes,
                   const uint64_t kyber_eta, RAND_STATE *rand);

void indcpa_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins,
               const uint64_t kyber_k,
               const uint64_t kyber_polyveccompressedbytes,
               const uint64_t kyber_eta,
               const uint64_t kyber_polyvecbytes,
               const uint64_t kyber_polycompressedbytes);

void indcpa_dec(unsigned char *m,
               const unsigned char *c,
               const unsigned char *sk,
               const uint64_t kyber_k,
               const uint64_t kyber_polyveccompressedbytes,
               const uint64_t kyber_polycompressedbytes);

#endif
