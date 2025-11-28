import os
import re
import csv
import argparse
from collections import defaultdict

def extract_cycles_by_mode(input_dir, output_dir):
    # Estrutura: operação -> modo -> lista de valores
    data = {
        'GenKey': defaultdict(list),
        'Sign': defaultdict(list),
        'Verify': defaultdict(list),
    }

    # Regex para extrair: operação e valor
    pattern = re.compile(r'Total CPU cycles for (GenKey|Sign|Verify) Mode (\d+): (\d+)')

    for filename in sorted(os.listdir(input_dir)):
        if not re.match(r'.+_mode_[1-8]\.log$', filename):
            continue

        filepath = os.path.join(input_dir, filename)
        with open(filepath, 'r') as file:
            for line in file:
                match = pattern.search(line)
                if match:
                    operation, mode, value = match.groups()
                    data[operation][int(mode)].append(int(value))

    # Cria diretório de saída se não existir
    os.makedirs(output_dir, exist_ok=True)

    for operation in data:
        # Obtem todos os modos ordenados
        modes = sorted(data[operation].keys())
        # Define o maior número de amostras entre os modos
        max_rows = max(len(data[operation][m]) for m in modes)

        # Gera caminho do CSV
        csv_path = os.path.join(output_dir, f'{operation.lower()}.csv')
        with open(csv_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([str(m) for m in modes])  # Cabeçalho: 1,2,3,...

            for i in range(max_rows):
                row = []
                for m in modes:
                    values = data[operation][m]
                    row.append(values[i] if i < len(values) else '')  # preenche com vazio se faltar
                writer.writerow(row)

    print(f"CSVs gerados em: {output_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extrai ciclos de CPU por modo e operação em CSVs.')
    parser.add_argument('input_dir', help='Diretório com arquivos *_mode_[1-8].log')
    parser.add_argument('output_dir', help='Diretório de saída para os CSVs')

    args = parser.parse_args()
    extract_cycles_by_mode(args.input_dir, args.output_dir)
