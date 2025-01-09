import subprocess
import os
import random

# *** Configuration: ***
NUCLEI_BINARY = "nuclei"
TARGETS_FILE = os.getenv("TARGETS_FILE", "targets.txt")
TEMPLATES_LIST = [template for template in os.getenv('TEMPLATES_LIST', 'cves,misconfiguration,vulnerabilities').split(',') if template]
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "results.json")
ENABLE_OUTPUT_FILE = os.getenv("ENABLE_OUTPUT_FILE", "false").lower() == "true"
REQUEST_DELAY_SECONDS = os.getenv("REQUEST_DELAY", "1")
HEADER_NAME = os.getenv("HEADER_NAME", "X-Real-IP")
HEADER_VALUE = os.getenv("HEADER_VALUE", "random-ip")

# Exclude DNS Ips:
EXCLUDED_DNS_IPS = {
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8", 
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "185.228.168.9",
    "185.228.169.9",
}

def generate_random_public_ip():
    # Keep generated IPs until we find out that is excluded from private, reserved, and invalid IP ranges.
    while True:
        ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
        
        first_octet = int(ip.split('.')[0])
        second_octet = int(ip.split('.')[1])

        if (
            first_octet == 10 or
            (first_octet == 172 and 16 <= second_octet <= 31) or
            first_octet == 192 and second_octet == 168 or
            first_octet >= 224 or
            ip in EXCLUDED_DNS_IPS
        ):
            continue
        print(f"[INFO] Spoofed {HEADER_NAME} is using this IP: {ip}")
        return ip

def get_header_value():
    if HEADER_VALUE.lower() == "random-ip":
        return generate_random_public_ip()
    return HEADER_VALUE

def check_env_vars():
    print("Environment Variable Configuration:")
    print(f"NUCLEI_BINARY: {NUCLEI_BINARY}")
    print(f"TARGETS_FILE: {TARGETS_FILE} (Default: 'targets.txt')")
    print(f"TEMPLATES_LIST: {TEMPLATES_LIST} (Default: ['cves', 'misconfiguration', 'vulnerabilities'])")
    print(f"OUTPUT_FILE: {OUTPUT_FILE} (Default: 'results.json')")
    print(f"ENABLE_OUTPUT_FILE: {ENABLE_OUTPUT_FILE} (Default: 'false')")
    print(f"REQUEST_DELAY_SECONDS: {REQUEST_DELAY_SECONDS} (Default: '1')")
    print(f"HEADER_NAME: {HEADER_NAME} (Default: 'X-Real-IP')")
    print(f"HEADER_VALUE: {HEADER_VALUE} (Default: 'random-ip')")

def run_nuclei(targets_file, templates, output_file, enable_output, request_delay):
    try:
        if not os.path.exists(targets_file):
            print(f"[ERROR] Targets file not found: {targets_file}")
            exit(1)

        templates_arg = ",".join(templates)
        header_value = get_header_value()
        header = f"{HEADER_NAME}: {header_value}"

        command = [
            NUCLEI_BINARY,
            "-t", templates_arg,
            "-jsonl",  # JSON output for parsing
            "-rl", "1",
            "-rld", request_delay,
            "-list", targets_file,
            "-duc", # Disable update check
            "-H", header

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
