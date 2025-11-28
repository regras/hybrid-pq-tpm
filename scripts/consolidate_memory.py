# consolidate_memory.py
import glob
import csv
import os
import sys

def main(output_dir):
    files = glob.glob(os.path.join(output_dir, '*_memory_usage.txt'))
    data = {}
    
    for file in files:
        # Extrai o modo do nome do arquivo (ex: "4" de "2023-01-01_mode_4_memory_usage.txt")
        mode = os.path.basename(file).split('_mode_')[-1].split('_')[0]
        
        with open(file, 'r') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        
        # Extrai valores (ex: "Peak memory during 'create': 1024.00 KiB" -> 1024.00)
        create = lines[0].split(': ')[1].replace('KiB', '').strip() if len(lines) > 0 else 'N/A'
        sign = lines[1].split(': ')[1].replace('KiB', '').strip() if len(lines) > 1 else 'N/A'
        verify = lines[2].split(': ')[1].replace('KiB', '').strip() if len(lines) > 2 else 'N/A'
        
        data[mode] = {
            'create': create,
            'sign': sign,
            'verify': verify
        }
    
    # Escreve o CSV consolidado
    output_csv = os.path.join(output_dir, 'memory_usage.csv')
    with open(output_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Mode', 'Create (KiB)', 'Sign (KiB)', 'Verify (KiB)'])
        for mode in sorted(data.keys(), key=lambda x: int(x) if x.isdigit() else x):
            writer.writerow([mode, data[mode]['create'], data[mode]['sign'], data[mode]['verify']])
    
    print(f"Consolidated memory data saved to: {output_csv}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python consolidate_memory.py <output_dir>")
        sys.exit(1)
    main(sys.argv[1])