import sys
from datetime import datetime

def extract_peak_memory(massif_file, start_time, end_time):
    """
    Extract peak memory usage (in KiB) between start_time and end_time from the massif file.
    """
    with open(massif_file, 'r') as f:
        lines = f.readlines()

    peaks = []
    current_time = None
    current_heap_mem = 0
    current_stack_mem = 0

    for line in lines:
        if line.startswith('time='):
            current_time = int(line.split('=')[1])
        elif line.startswith('mem_heap_B='):
            current_heap_mem = int(line.split('=')[1])
        elif line.startswith('mem_stacks_B='):
            current_stack_mem = int(line.split('=')[1])
            if start_time <= current_time <= end_time:
                total_mem = current_heap_mem + current_stack_mem
                peaks.append(total_mem)

    if not peaks:
        return None

    # Converte o pico de bytes para KiB
    peak_memory_kib = max(peaks) / 1024
    return peak_memory_kib

def main():
    if len(sys.argv) != 10:
        # print("Usage: python3 parse_massif.py <massif_file> <start_create> <end_create> <start_sign> <end_sign> <start_quote> <end_quote> <start_verify> <end_verify> <output_dir> <mode>")
        print("Usage: python3 parse_massif.py <massif_file> <start_create> <end_create> <start_sign> <end_sign> <start_verify> <end_verify> <output_dir> <mode>")
        sys.exit(1)

    massif_file = sys.argv[1]
    start_create = int(sys.argv[2])
    end_create = int(sys.argv[3])
    start_sign = int(sys.argv[4])
    end_sign = int(sys.argv[5])
    # start_quote = int(sys.argv[6])
    # end_quote = int(sys.argv[7])
    start_verify = int(sys.argv[6])
    end_verify = int(sys.argv[7])
    output_dir = sys.argv[8]
    mode = sys.argv[9]

    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    peak_create = extract_peak_memory(massif_file, start_create, end_create)
    peak_sign = extract_peak_memory(massif_file, start_sign, end_sign)
    # peak_quote = extract_peak_memory(massif_file, start_quote, end_quote)
    peak_verify = extract_peak_memory(massif_file, start_verify, end_verify)

    print(f"Peak memory during 'create': {peak_create:.2f} KiB" if peak_create else "No data")
    print(f"Peak memory during 'sign': {peak_sign:.2f} KiB" if peak_sign else "No data")
    # print(f"Peak memory during 'quote': {peak_quote:.2f} KiB" if peak_quote else "No data")
    print(f"Peak memory during 'verify': {peak_verify:.2f} KiB" if peak_verify else "No data")

    with open(f"{output_dir}/{current_datetime}_mode_{mode}_memory_usage.txt", 'a') as f:
        f.write(f"Peak memory during 'create': {peak_create:.2f} KiB\n" if peak_create else "No data\n")
        f.write(f"Peak memory during 'sign': {peak_sign:.2f} KiB\n" if peak_sign else "No data\n")
        # f.write(f"Peak memory during 'quote': {peak_quote:.2f} KiB\n" if peak_quote else "No data\n")
        f.write(f"Peak memory during 'verify': {peak_verify:.2f} KiB\n" if peak_verify else "No data\n")

if __name__ == "__main__":
    main()