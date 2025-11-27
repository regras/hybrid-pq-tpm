#include "ecc_utils.h"

// Função para imprimir buffer em hexadecimal
void print_buffer(const uint8_t* buffer, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02X", buffer[i]);
        if (i < length - 1) {
            printf(":");
        }
    }
    printf("\n");
}

// Serialização da chave pública
unsigned char* get_serialized_public_key(EVP_PKEY* keyPair, size_t* keyLen) {
    if (keyPair == NULL || keyLen == NULL) {
        fprintf(stderr, "Erro: Parâmetro inválido.\n");
        return NULL;
    }

    if (EVP_PKEY_get_octet_string_param(keyPair, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, keyLen) != 1) {
        fprintf(stderr, "Erro: Falha ao obter tamanho da chave pública.\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    unsigned char* serializedPublicKey = (unsigned char*)OPENSSL_malloc(*keyLen);
    if (serializedPublicKey == NULL) {
        fprintf(stderr, "Erro: Falha ao alocar memória.\n");
        return NULL;
    }

    if (EVP_PKEY_get_octet_string_param(keyPair, OSSL_PKEY_PARAM_PUB_KEY, serializedPublicKey, *keyLen, keyLen) != 1) {
        fprintf(stderr, "Erro: Falha ao serializar a chave pública.\n");
        ERR_print_errors_fp(stderr);
        OPENSSL_free(serializedPublicKey);
        return NULL;
    }

    return serializedPublicKey;
}

// Desserialização da chave pública
EVP_PKEY* get_deserialize_public_key(unsigned char* serializedPublicKey, size_t serializedPublicKeyLen, const char* curveName) {
    OSSL_PARAM_BLD* paramBuild = OSSL_PARAM_BLD_new();
    if (paramBuild == NULL) {
        fprintf(stderr, "Erro ao criar OSSL_PARAM_BLD.\n");
        return NULL;
    }

    if (OSSL_PARAM_BLD_push_utf8_string(paramBuild, OSSL_PKEY_PARAM_GROUP_NAME, curveName, 0) != 1) {
        OSSL_PARAM_BLD_free(paramBuild);
        fprintf(stderr, "Erro ao definir o nome da curva.\n");
        return NULL;
    }

    if (OSSL_PARAM_BLD_push_octet_string(paramBuild, OSSL_PKEY_PARAM_PUB_KEY, serializedPublicKey, serializedPublicKeyLen) != 1) {
        OSSL_PARAM_BLD_free(paramBuild);
        fprintf(stderr, "Erro ao definir a chave pública serializada.\n");
        return NULL;
    }

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(paramBuild);
    if (params == NULL) {
        OSSL_PARAM_BLD_free(paramBuild);
        fprintf(stderr, "Erro ao converter OSSL_PARAM_BLD para OSSL_PARAM.\n");
        return NULL;
    }

    EVP_PKEY_CTX* publicKeyCtx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (publicKeyCtx == NULL) {
        OSSL_PARAM_BLD_free(paramBuild);
        OSSL_PARAM_free(params);
        fprintf(stderr, "Erro ao criar contexto de chave pública.\n");
        return NULL;
    }

    if (EVP_PKEY_fromdata_init(publicKeyCtx) <= 0) {
        OSSL_PARAM_BLD_free(paramBuild);
        OSSL_PARAM_free(params);
        EVP_PKEY_CTX_free(publicKeyCtx);
        fprintf(stderr, "Erro ao inicializar contexto EVP_PKEY.\n");
        return NULL;
    }

    EVP_PKEY* publicKey = NULL;
    if (EVP_PKEY_fromdata(publicKeyCtx, &publicKey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        OSSL_PARAM_BLD_free(paramBuild);
        OSSL_PARAM_free(params);
        EVP_PKEY_CTX_free(publicKeyCtx);
        fprintf(stderr, "Erro ao criar a chave pública a partir dos dados.\n");
        return NULL;
    }

    OSSL_PARAM_BLD_free(paramBuild);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(publicKeyCtx);

    return publicKey;
}

// Serialização da chave privada
unsigned char* get_serialized_private_key(EVP_PKEY* keyPair, size_t* keyLen) {
    if (keyPair == NULL || keyLen == NULL) {
        fprintf(stderr, "Erro: Parâmetro inválido.\n");
        return NULL;
    }

    BIGNUM* privateKey = NULL;
    if (EVP_PKEY_get_bn_param(keyPair, OSSL_PKEY_PARAM_PRIV_KEY, &privateKey) != 1) {
        fprintf(stderr, "Erro: Falha ao obter a chave privada.\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    *keyLen = BN_num_bytes(privateKey);
    unsigned char* serializedPrivateKey = (unsigned char*)OPENSSL_malloc(*keyLen);
    if (serializedPrivateKey == NULL) {
        fprintf(stderr, "Erro: Falha ao alocar memória.\n");
        BN_free(privateKey);
        return NULL;
    }

    BN_bn2bin(privateKey, serializedPrivateKey);
    BN_free(privateKey);

    return serializedPrivateKey;
}

// Desserialização da chave privada para curvas NIST
EVP_PKEY* get_deserialize_private_key(unsigned char* serializedPrivateKey, size_t keyLen, const char* curveName) {
    if (serializedPrivateKey == NULL || keyLen == 0 || curveName == NULL) {
        fprintf(stderr, "Erro: Parâmetro inválido.\n");
        return NULL;
    }

    BIGNUM* privateKey = BN_bin2bn(serializedPrivateKey, keyLen, NULL);
    if (privateKey == NULL) {
        fprintf(stderr, "Erro: Falha ao desserializar a chave privada.\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Criação do parâmetro build
    OSSL_PARAM_BLD* paramBuild = OSSL_PARAM_BLD_new();
    if (paramBuild == NULL) {
        fprintf(stderr, "Erro ao criar OSSL_PARAM_BLD.\n");
        BN_free(privateKey);
        return NULL;
    }

    // Configura o nome da curva
    if (OSSL_PARAM_BLD_push_utf8_string(paramBuild, OSSL_PKEY_PARAM_GROUP_NAME, curveName, 0) != 1) {
        fprintf(stderr, "Erro ao definir o nome da curva.\n");
        BN_free(privateKey);
        OSSL_PARAM_BLD_free(paramBuild);
        return NULL;
    }

    // Configura a chave privada
    if (OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_PRIV_KEY, privateKey) != 1) {
        fprintf(stderr, "Erro ao definir a chave privada.\n");
        BN_free(privateKey);
        OSSL_PARAM_BLD_free(paramBuild);
        return NULL;
    }

    // Converter OSSL_PARAM_BLD para OSSL_PARAM
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(paramBuild);
    if (params == NULL) {
        fprintf(stderr, "Erro ao converter OSSL_PARAM_BLD para OSSL_PARAM.\n");
        OSSL_PARAM_BLD_free(paramBuild);
        BN_free(privateKey);
        return NULL;
    }

    // Criar contexto da chave privada
    EVP_PKEY_CTX* privateKeyCtx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (privateKeyCtx == NULL) {
        fprintf(stderr, "Erro ao criar contexto de chave privada.\n");
        OSSL_PARAM_BLD_free(paramBuild);
        OSSL_PARAM_free(params);
        BN_free(privateKey);
        return NULL;
    }

    // Inicializar o contexto EVP_PKEY
    if (EVP_PKEY_fromdata_init(privateKeyCtx) <= 0) {
        fprintf(stderr, "Erro ao inicializar contexto EVP_PKEY.\n");
        OSSL_PARAM_BLD_free(paramBuild);
        OSSL_PARAM_free(params);
        EVP_PKEY_CTX_free(privateKeyCtx);
        BN_free(privateKey);
        return NULL;
    }

    // Criar objeto chave privada
    EVP_PKEY* privateKeyObj = NULL;
    if (EVP_PKEY_fromdata(privateKeyCtx, &privateKeyObj, EVP_PKEY_KEYPAIR, params) <= 0) {
        fprintf(stderr, "Erro ao criar a chave privada a partir dos dados.\n");
        OSSL_PARAM_BLD_free(paramBuild);
        OSSL_PARAM_free(params);
        EVP_PKEY_CTX_free(privateKeyCtx);
        BN_free(privateKey);
        return NULL;
    }

    // Liberar recursos
    OSSL_PARAM_BLD_free(paramBuild);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(privateKeyCtx);
    BN_free(privateKey);

    return privateKeyObj;
}

