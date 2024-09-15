//Felipe
#include <stddef.h>
#include <stdint.h>

#define ED25519_KEY_SIZE 32

#if defined(_WIN32)
#define HYBRID_API __declspec(dllexport)
#else
#define HYBRID_API __attribute__((visibility("default")))
#endif

#if defined(HYBRID_SYS_UEFI)
#undef HYBRID_API
#define HYBRID_API
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#define CRYPTO_DILITHIUM_HYBRID_ALGNAME          "dilithium-ed25519"

HYBRID_API int crypto_sign_dilithium_ed25519_keypair(unsigned char* pk, unsigned char* sk);

HYBRID_API int crypto_sign_dilithium_ed25519(unsigned char* sm, unsigned long long* smlen,
	const unsigned char* m, unsigned long long mlen,
	const unsigned char* sk);

HYBRID_API int crypto_sign_dilithium_ed25519_open(unsigned char* m, unsigned long long* mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

HYBRID_API int crypto_verify_dilithium_ed25519(const unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

HYBRID_API int crypto_verify_dilithium(const unsigned char* m, unsigned long long mlen,
	const unsigned char* sm, unsigned long long smlen,
	const unsigned char* pk);

#if defined(__cplusplus)
} // extern "C"
#endif
