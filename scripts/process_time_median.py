import json
import os

def extract_median_from_json(json_file):
    with open(json_file, 'r') as file:
        data = json.load(file)
    # Supondo que a estrutura do JSON está correta e contém pelo menos uma entrada em "results"
    median = data['results'][0]['median']
    return median * 1000  # Convertendo segundos para milissegundos

def main(output_dir, sufixo):
    operations = ['create', 'sign', 'quote', 'verify']
    medians = {}

    for operation in operations:
        json_file = os.path.join(output_dir, f'hyperfine_{sufixo}_{operation}.json')
        if os.path.exists(json_file):
            medians[operation] = extract_median_from_json(json_file)
        else:
            print(f"Arquivo {json_file} não encontrado.")

    # Salvando os resultados em um arquivo de texto
    mediana_file = os.path.join(output_dir, f'hyperfine_{sufixo}_mediana.txt')
    with open(mediana_file, 'w') as file:
        for operation in operations:
            if operation in medians:
                file.write(f"{operation}: {medians[operation]:.3f} ms\n")
            else:
                file.write(f"{operation}: Dados não encontrados\n")

    # Exibindo os resultados
    print("Resultados das medianas:")
    for operation in operations:
        if operation in medians:
            print(f"{operation}: {medians[operation]:.3f} ms")
        else:
            print(f"{operation}: Dados não encontrados")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Uso: python extract_median.py <OUTPUT_DIR> <SUFIXO>")
        sys.exit(1)

    output_dir = sys.argv[1]
    sufixo = sys.argv[2]
    main(output_dir, sufixo)