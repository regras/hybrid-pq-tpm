# hybrid-pq-tpm
A hybrid and optimized implementation of Post-Quantum Trusted Platform Module using swTPM.

The measurement suite covers three categories:

- **CPU cycles**
- **Execution time**
- **Memory usage (Valgrind/Massif)**

The main entry point is `get_measures.sh`, which orchestrates TPM initialization, execution of cryptographic commands, measurement collection, and result consolidation.

---

## 1. Directory Structure

```
scripts/
 ├── get_measures.sh
 ├── commands.txt
 ├── build_env3.sh
 ├── parse_massif.py
 ├── consolidate_memory.py
 ├── xcycles2csv.py
 ├── process_cpu_cycles.py
 ├── process_time_median.py
 └── process_hyperfine_graphs.py
```

> All Python scripts listed above are **required**, since `get_measures.sh` calls them automatically.

---

## 2. Command File: `commands.txt`

Defines the TPM commands executed during the test pipeline.  
Example:

**ECC**: 
```
powerup: powerup
startup: startup
createprimary: createprimary -rsa -hi p -pwdk SENHA_CHAVE_EK -tk pritk.bin -ch prich.bin
create: create -hp 80000000 -si -ecc {CURVE} -kt f -kt p -opr dil_priv.bin -opu dil_pub.bin -pwdp SENHA_CHAVE_EK -pwdk SENHA_CHAVE_MLDSA
load: load -hp 80000000 -ipr dil_priv.bin -ipu dil_pub.bin -pwdp SENHA_CHAVE_EK
sign: sign -hk 80000001 -ecc -if component_to_sign.txt -os sig.bin -pwdk SENHA_CHAVE_MLDSA
verify: verifysignature -hk 80000001 -ecc -if component_to_sign.txt -is sig.bin
pcrread: pcrread -ha 0 -ahalg sha256
pcrextend: pcrextend -ha 0 -halg sha256 -ic teste
```

**PQC**: 
```
powerup: powerup
startup: startup
createprimary: createprimary -rsa -hi p -pwdk SENHA_CHAVE_EK -tk pritk.bin -ch prich.bin
create: create -hp 80000000 -si -dilithium mode={MODE} -kt f -kt p -opr dil_priv.bin -opu dil_pub.bin -pwdp SENHA_CHAVE_EK -pwdk SENHA_CHAVE_MLDSA
load: load -hp 80000000 -ipr dil_priv.bin -ipu dil_pub.bin -pwdp SENHA_CHAVE_EK
sign: sign -hk 80000001 -dilithium -if component_to_sign.txt -os sig.bin -pwdk SENHA_CHAVE_MLDSA
quote: quote -hp 0x04 -hk 0x80000001 -salg dilithium -pwdk SENHA_CHAVE_MLDSA -halg sha256 -palg sha256 -qd component_to_sign.txt -os quote_sig.bin -oa attestation.bin
verify: verifysignature -hk 80000001 -dilithium -if component_to_sign.txt -is sig.bin
pcrread: pcrread -ha 0 -ahalg sha256
pcrextend: pcrextend -ha 0 -halg sha256 -ic teste
```

The script dynamically loads each command by its key.

---

## 3. Main Script: `get_measures.sh`

This script is responsible for:

- Resetting the TPM environment (`NVChip` removed)
- Selecting PQC/hybrid or traditional ECC mode
- Launching the SW-TPM:
  - With **taskset** for CPU/time measurements
  - With **Valgrind/Massif** for memory measurements
- Executing the sequence:
  - `powerup`
  - `startup`
  - `createprimary`
  - `create`
  - `load`
  - `sign`
  - `verify`
- Consolidating results into CSV/JSON
- Organizing output into structured folders

---

## 4. Usage

### Syntax

```bash
./get_measures.sh     --cfile commands.txt     --pqc <true|false>     --measure <cpu|memory|time>     --tss <TSS_DIR>     --swtpm <SWTPM_DIR>     --sufix <LABEL>     [--num-tests N]
```

### Parameters

| Parameter    | Description |
|--------------|-------------|
| `--cfile`    | Path to `commands.txt` |
| `--pqc`      | `true` enables PQC (MLDSA) and Hybrid schemes (MLDSA + NIST or Edwards curves at different levels of security), `false` runs traditional ECC only|
| `--measure`  | Metric type (`cpu`, `memory`, `time`) |
| `--tss`      | Path to TSS installation directory |
| `--swtpm`    | Path to modified SW-TPM binaries |
| `--sufix`    | Measurement scenario label (e.g., `pqc`) |
| `--num-tests`| Number of repetitions (default: 10) |

---

## 5. Execution Flow

### 5.1 TPM Initialization

- Deletes `NVChip`
- Starts the TPM server
- Runs:
  - `powerup`
  - `startup`
  - `createprimary`

### 5.2 Mode Execution

The script selects multiple modes:

- PQC enabled: `MODES=(1 2 3 4 5 6 7 8)`
- ECC only: `MODES=(4 5 6 7 8)`

For each mode:
- Executes `create`
- Executes `load`
- Executes `sign`
- Executes `verify`
- Measures execution time or collects CPU/memory data

### 5.3 Consolidation

#### CPU metrics
Processed using:
- `xcycles2csv.py`
- `process_cpu_cycles.py`

#### Time metrics
Processed using:
- `hyperfine`
- `process_time_median.py`
- `process_hyperfine_graphs.py`

#### Memory metrics
Processed using:
- `parse_massif.py`
- `consolidate_memory.py`

---

## 6. Output Structure

After execution:

```
medidas/
 └── <SUFIXO>/
     ├── cpu/
     ├── time/
     └── memory/
```

Each mode also produces its own directory:

```
medidas/<SUFIXO>/<type>/<MODE>/*
```

---

## 7. Environment Requirements

### 7.1 Required Tools

- `hyperfine`
- `python3`
- `valgrind`
- `screen`
- `taskset` (util-linux)
- `tpm2-tss` built locally
- PQC-enabled SW-TPM binaries

### 7.2 Python Dependencies

Install via:

```bash
pip install numpy pandas matplotlib
```

---

## 8. Example Executions

### CPU cycles (PQC hybrid)

```bash
./get_measures.sh   --cfile commands.txt   --pqc true   --measure cpu   --tss ~/tpm2-tss/install   --swtpm ~/swtpm-hybrid/build/src   --sufix env3-n1
```

### Memory usage (Massif)

```bash
./get_measures.sh   --cfile commands.txt   --pqc true   --measure memory   --tss ~/tpm2-tss/install   --swtpm ~/swtpm-hybrid/build/src   --sufix env3-n3
```

### Execution time (hyperfine)

```bash
./get_measures.sh   --cfile commands.txt   --pqc false   --measure time   --tss ~/tpm2-tss/install   --swtpm ~/swtpm-hybrid/build/src   --sufix env1
```
---

## Published Articles
### SBSeg24 - Requirements for a Hybrid TPM Based on Optimized ML-DSA Post-Quantum Signature

The measurements were performed on a machine with the following hardware and software specifications:
- **CPU**: Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz, 4 cores (virtualized)
- **RAM**: 6 GB
- **Operating System**: Ubuntu 18.04.6 LTS
- **OpenSSL Version**: 1.1.1

To install the correct version of OpenSSL, please visit: [https://github.com/open-quantum-safe/openssl](https://github.com/open-quantum-safe/openssl)

---

### SIoT24 - A Low-Memory Implementation of a Hybrid Trusted Platform Module

The measurements were performed on a machine with the following hardware and software specifications:
- **CPU**: Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz
- **RAM**: 6 GB
- **Operating System**: Ubuntu 24.04 LTS, Kernel 6.8.0-41
- **OpenSSL Version**: 3.0.13 (30 Jan 2024)

Additionally, install the OQS Provider by visiting: [https://github.com/open-quantum-safe/oqs-provider](https://github.com/open-quantum-safe/oqs-provider)
