#!/bin/bash

# Função para exibir o uso do script
function usage() {
    echo "Uso: $0 --cfile <FILE> --pqc <true|false> --measure <cpu|memory|time> --tss <DIR> --swtpm <DIR> --sufix <SUFIXO> [--num-tests <N>, default N=10]"
    exit 1
}

# Verifica se o número correto de parâmetros foi fornecido
if [ "$#" -lt 8 ]; then
    usage
fi

# Limpa o NVChip caso alguma configuração do TPM (como NVRAM) tenha sido alterada
rm -rf NVChip

# Define o valor padrão de NUM_TESTS como 10
NUM_TESTS=10

# Processa os parâmetros de entrada
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --cfile) COMMANDS_FILE="$2"; shift ;;
        --pqc) PQC="$2"; shift ;;
        --measure) MEASURE_TYPE="$2"; shift ;;
        --tss) TSS_DIR="$2"; shift ;;
        --swtpm) SWTPM_DIR="$2"; shift ;;
        --sufix) SUFIXO="$2"; shift ;;
        --num-tests) NUM_TESTS="$2"; shift ;;
        *) echo "Parâmetro desconhecido: $1"; usage ;;
    esac
    shift
done

#export OPENSSL_LIB_PATH="/usr/bin/openssl"
export OPENSSL_LIB_PATH=$HOME/openssl3
export LD_LIBRARY_PATH=$OPENSSL_LIB_PATH/lib64:$LD_LIBRARY_PATH:$TSS_DIR/utils
export PATH="$OPENSSL_LIB_PATH/bin:$PATH"

# Diretório base é o diretório onde o script está sendo executado
BASE_DIR="$(pwd)"


# Carrega os comandos do arquivo commands.txt
declare -A commands

while IFS=': ' read -r key value; do
    commands["$key"]="$TSS_DIR/utils/$value"
done < "$COMMANDS_FILE"

# Caminhos e arquivos utilizados
SESSION_NAME="tpmserver_session"
if [ "$MEASURE_TYPE" == "memory" ]; then
    TPMSERVER="$SWTPM_DIR/tpm_server"
else 
    TPMSERVER="taskset --cpu-list 0 $SWTPM_DIR/tpm_server"
fi

OUTPUT_DIR="$BASE_DIR/medidas/$SUFIXO/$MEASURE_TYPE/"

# ========================================================
# Exibe informações iniciais
# ========================================================
echo "============================="
echo "Tipo de medição: $MEASURE_TYPE"
echo "Diretório base: $BASE_DIR"
echo "Caminho do tpm_server: $TPMSERVER"
echo "Arquivo de saída do Valgrind: $VALGRIND_OUT"
echo "Diretório de saída: $OUTPUT_DIR"
echo "Sufixo dos arquivos: $SUFIXO"
echo "Hyperfine: $HYPERFINE"
echo "Número de testes: $NUM_TESTS"
echo "============================="

# ========================================================
# Criação da estrutura de diretórios necessária (caso não exista)
# ========================================================
echo ">>> Criando diretórios necessários..."
mkdir -p "$OUTPUT_DIR"
echo ">>> Diretórios criados com sucesso."

# Define os valores de MODE com base em PQC
if [ "$PQC" == "true" ]; then
    MODES=(1 2 3 4 5 6 7 8)
    ./build_env3.sh $SWTPM_DIR TRUE
else
    # MODES=("nistp256" "nistp384")
    MODES=(4 5 6 7 8)
    ./build_env3.sh $SWTPM_DIR FALSE
fi

# Executa os comandos para os modos definidos
for MODE in "${MODES[@]}"; do

    TPMSERVER_LOG="$OUTPUT_DIR/swtpm_${SUFIXO}_mode_${MODE}.log"
    TPMSERVER_LOG_FILTER="$OUTPUT_DIR/${SUFIXO}_mode_${MODE}.log"
    VALGRIND_OUT="$OUTPUT_DIR/massif_${MODE}.out"

    # ========================================================
    # Escolhe o tipo de medição (CPU ou Memória)
    # ========================================================
    if [ "$MEASURE_TYPE" == "memory" ]; then
        echo ">>> Iniciando tpmserver com Valgrind e screen em background..."
        start_massif=$(($(date +%s%N)/1000000))
        
        # Executa em screen com log detalhado
        screen -L -Logfile "$TPMSERVER_LOG" -dmS $SESSION_NAME bash -c \
            "valgrind --tool=massif --stacks=yes --time-unit=ms --massif-out-file=$VALGRIND_OUT $TPMSERVER"
        
        echo ">>> Valgrind iniciado na sessão '$SESSION_NAME'. Log: $TPMSERVER_LOG"


    elif [ "$MEASURE_TYPE" == "cpu" ] || [ "$MEASURE_TYPE" == "time" ]; then
        echo ">>> Iniciando tpmserver em background para medição de CPU/Tempo..."
        stdbuf -oL $TPMSERVER > "$TPMSERVER_LOG" 2>&1 &     
        TPMSERVER_PID=$!
        echo ">>> swtpm PID '$TPMSERVER_PID'."
    else
        echo "Tipo de medição inválido. Use 'cpu', 'memory' ou 'time'."
        exit 1
    fi

    sleep 2

    # ========================================================
    # Pausa para garantir que o tpmserver tenha tempo suficiente para inicializar
    # ========================================================
    echo ">>> Inicializando o SW-TPM (powerup e startup)..."
    ${commands["powerup"]}
    sleep 1
    ${commands["startup"]}
    sleep 1

    # ========================================================
    # Executa o comando 'createprimary' - Sem medição
    # ========================================================
    echo ">>> Executando comando 'createprimary'..."
    ${commands["createprimary"]}
    echo ">>> Comando 'createprimary' executado."

    # ========================================================
    # Executa o comando 'create' e captura o tempo com ou sem hyperfine
    # ========================================================
    echo ">>> Executando comando 'create'..."

    # sync; echo 3 | tee /proc/sys/vm/drop_caches

    start_create=0
    current_create="${commands["create"]//\{MODE\}/$MODE}"

    echo $current_create
    
    if [ "$MEASURE_TYPE" == "time" ]; then
        hyperfine --runs "$NUM_TESTS" --warmup 3 --export-json "$OUTPUT_DIR/hyperfine_${SUFIXO}_mode_${MODE}_create.json" \
            "${current_create}"
    else
        start_create=$(($(date +%s%N)/1000000 - start_massif))
        for ((i=1; i<=NUM_TESTS; i++)); do
            ${current_create}
        done
    fi
    end_create=$(($(date +%s%N)/1000000 - start_massif))
    echo ">>> Comando 'create' executado. Tempo registrado."

    # ========================================================
    # Executa o comando 'Load' - Sem medição
    # ========================================================
    echo ">>> Executando comando 'Load' para carregar chaves MLDSA..."
    ${commands["load"]}
    echo ">>> Comando 'load' executado."

    # ========================================================
    # Executa o comando 'sign' e captura o tempo com ou sem hyperfine
    # ========================================================
    echo ">>> Executando comando 'sign'..."
    # sync; echo 3 | tee /proc/sys/vm/drop_caches

    start_sign=0
    if [ "$MEASURE_TYPE" == "time" ]; then
        hyperfine --runs "$NUM_TESTS" --warmup 3 --export-json "$OUTPUT_DIR/hyperfine_${SUFIXO}_mode_${MODE}_sign.json" \
            "${commands["sign"]}"
    else
        start_sign=$(($(date +%s%N)/1000000 - start_massif))
        for ((i=1; i<=NUM_TESTS; i++)); do
            ${commands["sign"]}
        done
    fi
    end_sign=$(($(date +%s%N)/1000000 - start_massif))
    echo ">>> Comando 'sign' executado. Tempo registrado."

    # ========================================================
    # Executa o comando 'verify' e captura o tempo com ou sem hyperfine
    # ========================================================
    echo ">>> Executando comando 'verify'..."
    # sync; echo 3 | tee /proc/sys/vm/drop_caches

    start_verify=0
    if [ "$MEASURE_TYPE" == "time" ]; then
        hyperfine --runs "$NUM_TESTS" --warmup 3 --export-json "$OUTPUT_DIR/hyperfine_${SUFIXO}_mode_${MODE}_verify.json" \
            "${commands["verify"]}"
    else
        start_verify=$(($(date +%s%N)/1000000 - start_massif))
        for ((i=1; i<=NUM_TESTS; i++)); do
            ${commands["verify"]}
        done
    fi
    end_verify=$(($(date +%s%N)/1000000 - start_massif))
    echo ">>> Comando 'verify' executado. Tempo registrado."

    # ========================================================
    # Finaliza o Valgrind e chama o script Python para processar os dados
    # ========================================================
    if [ "$MEASURE_TYPE" == "memory" ]; then
    echo ">>> Finalizando a sessão do screen de forma controlada..."
    
    # 1. Envia sinal de término para o Valgrind
    screen -S $SESSION_NAME -X stuff $'\003'  # Envia CTRL+C
    sleep 1
    
    # 2. Encerra o screen e espera finalização
    screen -S $SESSION_NAME -X quit
    sleep 2  # Tempo extra para Valgrind finalizar
    
    # 3. Força término se necessário
    if screen -list | grep -q $SESSION_NAME; then
        echo ">>> Forçando término da sessão..."
        screen -S $SESSION_NAME -X kill
        sleep 1
    fi
    
    # 4. Verifica se o arquivo foi gerado
    if [ ! -f "$VALGRIND_OUT" ]; then
        echo ">>> AVISO: Arquivo do Valgrind não encontrado!"
        exit 1
    elif [ ! -s "$VALGRIND_OUT" ]; then
        echo ">>> AVISO: Arquivo do Valgrind está vazio!"
        exit 1
    else
        echo ">>> Arquivo do Valgrind gerado: $(du -h $VALGRIND_OUT)"
    fi
        python3 parse_massif.py $VALGRIND_OUT \
                $start_create $end_create \
                $start_sign $end_sign \
                $start_verify $end_verify \
                "$OUTPUT_DIR" \
                "$MODE"

        echo ">>> Processamento de memória para o modo $MODE concluído."
    else
        echo ">>> Finalizando o TPMServer..."
        kill $TPMSERVER_PID
    fi

    grep "Total CPU cycles for " $TPMSERVER_LOG > "$TPMSERVER_LOG_FILTER"
    rm -rf "$TPMSERVER_LOG"

    # Limpa os arquivos temporários
    mkdir $OUTPUT_DIR$MODE
    cp *.bin $OUTPUT_DIR$MODE/
    rm -rf dil_priv.bin dil_pub.bin h80000000.bin h80000001.bin hp80000000.bin hp80000001.bin prich.bin pritk.bin sig.bin
    # sync; echo 3 | tee /proc/sys/vm/drop_caches

if [ "$MEASURE_TYPE" == "cpu" ]; then
    echo ">>> Consolidando dados de CPU..."
    python3 xcycles2csv.py "$OUTPUT_DIR" "$OUTPUT_DIR/consolidated"
    python3 process_cpu_cycles.py "$TPMSERVER_LOG_FILTER" "$OUTPUT_DIR/consolidated"
elif [ "$MEASURE_TYPE" == "time" ]; then
    echo ">>> Consolidando dados de tempo..."
    python3 process_time_median.py "$OUTPUT_DIR" "$SUFIXO"
    python3 process_hyperfine_graphs.py "$OUTPUT_DIR" "$OUTPUT_DIR/consolidated"
elif [ "$MEASURE_TYPE" == "memory" ]; then
    echo ">>> Consolidando dados de memória..."
    python3 consolidate_memory.py "$OUTPUT_DIR"
fi
done