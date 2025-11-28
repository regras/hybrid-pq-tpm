import os
import json
import matplotlib.pyplot as plt

def generate_boxplots(json_dir, output_dir, y_limit=0.4):
    # Inicializa os dados agrupados por modo
    data_by_mode = {f"mode_{i}": {"create": [], "sign": [], "verify": [], "quote": []} for i in range(1, 9)}

    # Processa os arquivos JSON
    for filename in os.listdir(json_dir):
        if filename.startswith("hyperfine_PQC_mode_") and filename.endswith(".json"):
            filepath = os.path.join(json_dir, filename)
            with open(filepath, 'r') as f:
                content = json.load(f)
                times = content["results"][0]["times"]
            
            # Remove outliers acima do limite especificado
            times = [t for t in times if t <= y_limit]

            # Extrai o modo e a operação
            parts = filename.split("_")
            mode = parts[3]
            operation = parts[4].split(".")[0]  # Remove a extensão
            
            # Adiciona os tempos ao modo e operação correspondentes
            data_by_mode[f"mode_{mode}"][operation] = times

    # Cria o diretório de saída, se não existir
    os.makedirs(output_dir, exist_ok=True)

    # Gera os gráficos para cada modo
    for mode, operations in data_by_mode.items():
        plt.figure(figsize=(10, 6))
        
        # Dados e rótulos para o gráfico
        data = [operations["create"], operations["sign"], operations["verify"], operations["quote"]]
        labels = ["Create", "Sign", "Verify", "Quote"]
        
        plt.boxplot(data, labels=labels, patch_artist=True, boxprops=dict(facecolor='lightblue', color='blue'))
        plt.ylim(0, y_limit)  # Define o limite fixo para o eixo Y
        plt.yticks([i / 20 for i in range(0, int(y_limit * 20) + 1)])  # Define intervalos de 0.1 no eixo Y
        plt.title(f"Execution Times by Operation for {mode.capitalize()}")
        plt.ylabel("Time (seconds)")
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Salva o gráfico
        output_file = f"{output_dir}/Mode_{mode}_boxplot.svg"
        plt.savefig(output_file, format="svg")
        plt.close()

    print(f"Gráficos salvos em {output_dir}")

# Exemplo de execução:
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Uso: python script.py <diretorio_json> <diretorio_saida>")
        sys.exit(1)

    json_dir = sys.argv[1]
    output_dir = sys.argv[2]
    generate_boxplots(json_dir, output_dir)
