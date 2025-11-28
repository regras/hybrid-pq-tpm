import sys
import os
import re
import statistics
import matplotlib.pyplot as plt
import csv

def extract_cycles_by_mode(log_file, operations):
    """
    Extrai os ciclos de CPU para todas as operações e garante que o mesmo modo seja aplicado a todas.
    """
    pattern_with_mode = r"Total CPU cycles for (\w+) Mode (\d+): ([0-9]+(?:\.[0-9]+)?)"
    pattern_without_mode = r"Total CPU cycles for (\w+): ([0-9]+(?:\.[0-9]+)?)"
    data_by_mode = {}
    mode_mapping = {}  # Mapeia operações ao modo identificado

    with open(log_file, 'r') as file:
        for line in file:
            match_with_mode = re.search(pattern_with_mode, line)
            if match_with_mode:
                operation = match_with_mode.group(1)
                mode = match_with_mode.group(2)
                cycles = float(match_with_mode.group(3))

                # Atualiza o mapeamento de modo para a operação
                mode_mapping[operation] = mode
            else:
                match_without_mode = re.search(pattern_without_mode, line)
                if match_without_mode:
                    operation = match_without_mode.group(1)
                    cycles = float(match_without_mode.group(2))

                    # Usa o modo de 'GenKey' se disponível
                    mode = mode_mapping.get("GenKey", "NA")
                else:
                    continue  # Linha não corresponde a nenhum padrão

            if operation not in operations:
                continue

            # Garante que o modo está no dicionário de dados
            if mode not in data_by_mode:
                data_by_mode[mode] = {op: [] for op in operations}

            # Adiciona os ciclos ao modo correspondente
            data_by_mode[mode][operation].append(cycles)

    return data_by_mode


def calculate_statistics(cycles):
    """
    Calcula a média, mediana, maior e menor valor dos ciclos de CPU.
    """
    if not cycles:
        return None, None, None, None
    mean_value = statistics.mean(cycles)
    median_value = statistics.median(cycles)
    max_value = max(cycles)
    min_value = min(cycles)
    return mean_value, median_value, max_value, min_value

def write_statistics(output_dir, mode, stats_by_operation):
    """
    Escreve estatísticas em um arquivo de texto por modo.
    """
    output_file = os.path.join(output_dir, f"Mode_{mode}_cpu_stats.txt")

    with open(output_file, 'w') as file:
        file.write(f"Statistics for Mode {mode} CPU cycles:\n")
        for operation, stats in stats_by_operation.items():
            mean_value, median_value, max_value, min_value = stats
            file.write(f"{operation}:\n")
            file.write(f"  Mean: {mean_value}\n")
            file.write(f"  Median: {median_value}\n")
            file.write(f"  Max: {max_value}\n")
            file.write(f"  Min: {min_value}\n")

def write_csv(output_dir, mode, operation_data):
    """
    Escreve os dados de ciclos de CPU em um arquivo CSV por modo.
    """
    output_file = os.path.join(output_dir, f"Mode_{mode}_cpu_data.csv")
    
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Operation", "Cycle Index", "CPU Cycles"])
        for operation, cycles in operation_data.items():
            for idx, cycle in enumerate(cycles):
                writer.writerow([operation, idx + 1, cycle])

def generate_box_plot(data_by_operation, labels, output_file, title, ylabel):
    """
    Gera um boxplot agrupado por operação.
    """
    plt.figure(figsize=(10, 6))
    plt.boxplot(data_by_operation, labels=labels, patch_artist=True, boxprops=dict(facecolor='lightblue', color='blue'))
    plt.title(title)
    plt.ylabel(ylabel)
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Ajusta escala do eixo Y para múltiplos de 500.000
    max_y = max(max(data) for data in data_by_operation)  # Obtém o valor máximo de todos os dados
    #step = 1000000  # Intervalo de 500.000
    step = 200000

    # Define o limite superior do eixo Y como um múltiplo de 500.000
    upper_limit = (max_y // step + 1) * step  # O próximo múltiplo de 500.000 acima do valor máximo

    # Garantir que upper_limit seja um inteiro
    upper_limit = int(upper_limit)

    # Configura os ticks do eixo Y para múltiplos de 500.000
    ticks = range(0, upper_limit + step, step)
    plt.yticks(ticks)

    # Ajusta os limites do eixo Y
    plt.ylim(0, upper_limit)

    # Formatação dos números do eixo Y
    plt.gca().get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, _: f"{int(x)}"))

    plt.tight_layout()
    plt.savefig(output_file, format='svg')
    plt.close()



def main():
    if len(sys.argv) < 3:
        print("Uso: process_cpu_cycles.py <log_file> <output_dir>")
        sys.exit(1)

    log_file = sys.argv[1]
    output_dir = sys.argv[2]
    os.makedirs(output_dir, exist_ok=True)

    # Operações de interesse, mas 'Quote' não será incluído no gráfico
    operations = ["GenKey", "Sign", "Verify", "Quote"]

    # Extrair dados do log
    data_by_mode = extract_cycles_by_mode(log_file, operations)

    for mode, operation_data in data_by_mode.items():
        # Estatísticas por operação
        stats_by_operation = {
            op: calculate_statistics(cycles) for op, cycles in operation_data.items()
        }

        # Escrever estatísticas em arquivo
        write_statistics(output_dir, mode, stats_by_operation)

        # Escrever CSV com os dados
        write_csv(output_dir, mode, operation_data)

        # Gerar boxplot (excluindo a operação 'Quote' para o gráfico)
        labels = [op for op in operation_data.keys() if op != "Quote"]
        data = [operation_data[op] for op in labels]
        output_file = os.path.join(output_dir, f"Mode_{mode}_boxplot.svg")
        generate_box_plot(
            data, labels, output_file,
            title=f"CPU Cycle Distribution - Mode {mode}",
            ylabel="CPU Cycles"
        )

        print(f"Gráfico gerado para Modo {mode}: {output_file}")

if __name__ == "__main__":
    main()
