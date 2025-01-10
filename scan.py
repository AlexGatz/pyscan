import subprocess
import os
import random
import re
import sys

# *** Configuration: ***
NUCLEI_BINARY = "nuclei"
TARGETS_FILE = os.getenv("TARGETS_FILE", "targets.txt")
TEMPLATES_LIST = [
    stripped for template in os.getenv('TEMPLATES_LIST', 'cves,misconfiguration,vulnerabilities').split(',')
    if (stripped := template.strip())
]
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "results.json")
ENABLE_OUTPUT_FILE = os.getenv("ENABLE_OUTPUT_FILE", "false").lower() == "true"
REQUEST_DELAY_SECONDS = os.getenv("REQUEST_DELAY", "1")
HEADER_NAME = os.getenv("HEADER_NAME", "X-Real-IP")
HEADER_VALUE = os.getenv("HEADER_VALUE", "random-ip")

def validate_config():
    if not TARGETS_FILE or not isinstance(TARGETS_FILE, str):
        print(f"[ERROR] Invalid TARGETS_FILE: {TARGETS_FILE}. Must be a non-empty string.")
        sys.exit(1)

    if not TEMPLATES_LIST or not all(isinstance(template, str) and template.strip() for template in TEMPLATES_LIST):
        print(f"[ERROR] Invalid TEMPLATES_LIST: {TEMPLATES_LIST}. Must be a comma-separated list of non-empty strings.")
        sys.exit(1)

    if not OUTPUT_FILE or not OUTPUT_FILE.endswith(".json"):
        print(f"[ERROR] Invalid OUTPUT_FILE: {OUTPUT_FILE}. Must be a non-empty string ending with '.json'.")
        sys.exit(1)

    if not isinstance(ENABLE_OUTPUT_FILE, bool):
        print(f"[ERROR] Invalid ENABLE_OUTPUT_FILE: {ENABLE_OUTPUT_FILE}. Must be 'true' or 'false'.")
        sys.exit(1)

    if not REQUEST_DELAY_SECONDS.isdigit() or int(REQUEST_DELAY_SECONDS) < 1:
        print(f"[ERROR] Invalid REQUEST_DELAY: {REQUEST_DELAY_SECONDS}. Must be an integer >= 1.")
        sys.exit(1)

    if not HEADER_NAME or not isinstance(HEADER_NAME, str):
        print(f"[ERROR] Invalid HEADER_NAME: {HEADER_NAME}. Must be a non-empty string.")
        sys.exit(1)

    if HEADER_VALUE.lower() != "random-ip":
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not ip_pattern.match(HEADER_VALUE):
            print(f"[ERROR] Invalid HEADER_VALUE: {HEADER_VALUE}. Must be 'random-ip' or a valid IP address.")
            sys.exit(1)

    print("[INFO] All environment variables are valid.")

def validate_target_file(file_path):
    try:
        if not os.path.exists(file_path):
            raise ValueError(f"Target file '{file_path}' does not exist.")
        
        valid_targets = []
        # <ip> OR <ip>:<port>
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?$")
        # <host> OR <host>:<port>
        hostname_pattern = re.compile(r"^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*(?::[0-9]{1,5})?$")
        
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if ip_pattern.match(line) or hostname_pattern.match(line):
                    valid_targets.append(line)
                else:
                    raise ValueError(f"Invalid target format: '{line}' in file '{file_path}'.")
        
        if not valid_targets:
            raise ValueError(f"Target file '{file_path}' is empty or contains no valid targets.")
        
        return valid_targets  # Return the list of valid targets
    except Exception as e:
        print(f"[ERROR] {e}", flush=True)
        sys.exit(1)

def print_config():
    print("Environment Variable Configuration:")
    print(f"NUCLEI_BINARY: {NUCLEI_BINARY}")
    print(f"TARGETS_FILE: {TARGETS_FILE} (Default: 'targets.txt')")
    print(f"TEMPLATES_LIST: {TEMPLATES_LIST} (Default: ['cves', 'misconfiguration', 'vulnerabilities'])")
    print(f"OUTPUT_FILE: {OUTPUT_FILE} (Default: 'results.json')")
    print(f"ENABLE_OUTPUT_FILE: {ENABLE_OUTPUT_FILE} (Default: 'false')")
    print(f"REQUEST_DELAY_SECONDS: {REQUEST_DELAY_SECONDS} (Default: '1')")
    print(f"HEADER_NAME: {HEADER_NAME} (Default: 'X-Real-IP')")
    print(f"HEADER_VALUE: {HEADER_VALUE} (Default: 'random-ip')")

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
    validate_config()
    print_config()
    validate_target_file(TARGETS_FILE)
    run_nuclei(TARGETS_FILE, TEMPLATES_LIST, OUTPUT_FILE, ENABLE_OUTPUT_FILE, REQUEST_DELAY_SECONDS)

if __name__ == "__main__":
    main()
