import subprocess
import os

# *** Configuration: ***
NUCLEI_BINARY = "nuclei"
TARGETS_FILE = os.getenv("TARGETS_FILE", "targets.txt")
TEMPLATES_LIST = [template for template in os.getenv('TEMPLATES_LIST', 'cves,misconfiguration,vulnerabilities').split(',') if template]
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "results.json")
ENABLE_OUTPUT_FILE = os.getenv("ENABLE_OUTPUT_FILE", "false").lower() == "true"
REQUEST_DELAY_SECONDS = os.getenv("REQUEST_DELAY", "1")

def check_env_vars():
    print("Environment Variable Configuration:")
    print(f"NUCLEI_BINARY: {NUCLEI_BINARY}")
    print(f"TARGETS_FILE: {TARGETS_FILE} (Default: 'targets.txt')")
    print(f"TEMPLATES_LIST: {TEMPLATES_LIST} (Default: ['cves', 'misconfiguration', 'vulnerabilities'])")
    print(f"OUTPUT_FILE: {OUTPUT_FILE} (Default: 'results.json')")
    print(f"ENABLE_OUTPUT_FILE: {ENABLE_OUTPUT_FILE} (Default: 'false')")
    print(f"REQUEST_DELAY_SECONDS: {REQUEST_DELAY_SECONDS} (Default: '1')")

def run_nuclei(targets_file, templates, output_file, enable_output, request_delay):
    try:
        if not os.path.exists(targets_file):
            print(f"[ERROR] Targets file not found: {targets_file}")
            exit(1)

        templates_arg = ",".join(templates)

        command = [
            NUCLEI_BINARY,
            "-t", templates_arg,
            "-jsonl",  # JSON output for parsing
            "-rl", "1",
            "-rld", request_delay,
            "-list", targets_file,
            "-duc" # Disable update check
        ]

        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=True,
        )

        if enable_output:
            with open(output_file, "w") as f:
                f.write(result.stdout)
            print(f"[INFO] Scan completed. Results saved to {output_file}.")
        else:
            print("[INFO] Output file writing is disabled. Results are not saved.")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Nuclei scan failed: {e.stderr}")
        print(f"[DEBUG] Command: {e.cmd}")
        print(f"[DEBUG] Return Code: {e.returncode}")
        exit(1)


def main():
    check_env_vars()
    run_nuclei(TARGETS_FILE, TEMPLATES_LIST, OUTPUT_FILE, ENABLE_OUTPUT_FILE, REQUEST_DELAY_SECONDS)

if __name__ == "__main__":
    main()
