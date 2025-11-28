#!/bin/bash

# Verifica se o diretório foi passado como parâmetro
if [ "$#" -ne 2 ]; then
    echo "Uso: $0 <diretório> <TRUE|FALSE>"
    exit 1
fi

DIR="$1"
USE_HYBRID="$2"

export OPENSSL_LIB_PATH=$HOME/openssl3
export LD_LIBRARY_PATH=$OPENSSL_LIB_PATH/lib64:$LD_LIBRARY_PATH
export PATH="$OPENSSL_LIB_PATH/bin:$PATH"

# Verifica se o diretório existe
if [ ! -d "$DIR" ]; then
    echo "Diretório '$DIR' não encontrado."
    exit 1
fi

# Entra no diretório
cd "$DIR" || exit 1

# Executa make clean
make clean

# Define os arquivos-fonte conforme o modo (TRUE = híbrido, FALSE = ECC)
if [ "$USE_HYBRID" == "TRUE" ]; then
    cp CryptUtil-ENV3-HYBRID.c CryptUtil.c
    cp TpmTypes-ENV3-HYBRID.h TpmTypes.h
    cp CryptDilithium-ENV3-HYBRID.c CryptDilithium.c
elif [ "$USE_HYBRID" == "FALSE" ]; then
    cp CryptUtil-ENV3-ECC.c CryptUtil.c
    cp TpmTypes-ENV3-ECC.h TpmTypes.h
    cp CryptDilithium-ENV3-ECC.c CryptDilithium.c
else
    echo "Segundo argumento deve ser 'TRUE' ou 'FALSE'"
    exit 1
fi

# Executa make
make

# Finaliza
exit 0
