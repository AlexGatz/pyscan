# TX-Pyscan

tx-pyscan is a containerized wrapper for the Nuclei vulnerability scanner. It simplifies the process of executing scans against a specified list of targets by providing a consistent and bandwidth-efficient environment. The tool prevents redundant template downloads, supports dynamic configuration through environment variables, and includes input validation to ensure proper operation. It is designed for users who require a streamlined, repeatable scanning process with minimal overhead.

- Please review the [Project Discovery / Nuclei Project](https://github.com/projectdiscovery/nuclei.git) for more details about that tool.

## Important Note
#### <strong>Always start by double checking and updating the targets file before using this.</strong>
#### <strong>You do not want to accidentatly run this against an unknown device as this is executing actual active attack payloads.</strong>

## Build and Run Locally
### Requirements
- *Note: Only Mac and Linux supported at this time.*
- Install [Docker](https://docs.docker.com/desktop/)
- Install [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- Clone the repo: `git clone https://github.com/AlexGatz/tx-pyscan.git`
- Open or `cd` into the tx-pyscan directory.

### 3 Options (mac or linux):
#### Single line Build and Run Command (easiest)
`docker build -t tx-pyscan . && docker run --rm -v $(pwd)/targets.txt:/app/targets.txt tx-pyscan`

#### Basic Standalone Container with Custom Config (.env file)
`docker build -t tx-pyscan .`\
`docker run --rm --env-file .example-env -v $(pwd)/targets.txt:/app/targets.txt tx-pyscan`

#### Docker Compose Based Test with echo-server (development)
`docker compose up --build`\
*Note: The included target.txt file is meant for this compose file.*

## Configuation
#### Format: ENV_VAR=\<Default Setting> (details)
__TARGETS_FILE__=targets.txt (must be a filename or path and filename)\
__TEMPLATES_LIST__=cves,misconfiguration,vulnerabilities (single value or list)\
__ENABLE_OUTPUT_FILE__=false (enable nuclei output file to see final results)\
__OUTPUT_FILE__=results.json (only needed if ENABLE_OUTPUT_FILE=__true__, must mount file in docker run to get this output)\
__REQUEST_DELAY_SECONDS__=1 (only supports integers and adjust acording to needs)\
__HEADER_NAME__=X-Real-IP (default to X-Real-IP for spoofing)\
__HEADER_VALUE__=random-ip (default to random IP generation)\
*Note: Only single header customization is currently supported.*

## Disclaimer
This script is provided "as-is" without any express or implied warranties, including, but not limited to, the implied warranties of merchantability or fitness for a particular purpose. By using this script, you agree to the following terms:

Usage Responsibility:
    This script is intended for authorized security testing purposes only.
    It is the user's responsibility to ensure that any usage complies with applicable laws, regulations, and ethical guidelines.
    Unauthorized scanning or testing of systems that you do not own or have explicit permission to test may be illegal and could result in penalties.

Data and Privacy:
    The script may generate and store output files containing scan results. Users are responsible for handling these files securely and ensuring no sensitive information is exposed.

Security and Safety:
    This script interacts with external services and systems, which may have security implications. Users should run the script in a controlled environment, such as a containerized or isolated setup, to minimize potential risks.

No Liability:
    The author is not responsible for any damage, loss, or consequences arising from the use or misuse of this script. Use it at your own risk.

Third-Party Dependencies:
    This script uses external tools like nuclei. Users should ensure they understand and agree to the terms of use for these tools.

By proceeding to use this script, you acknowledge and accept these terms.