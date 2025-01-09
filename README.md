## Build and Run Locally
`docker build -t tx-pyscan .`\
`docker run --rm --env-file .example-env tx-pyscan`


## Configuation
#### Format: ENV_VAR=\<Default Setting> (details)
TARGETS_FILE=targets.txt (must be a filename or path and filename)\
TEMPLATES_LIST=cves,misconfiguration,vulnerabilities (single value or list)\
ENABLE_OUTPUT_FILE=false (enable nuclei output file to see final results)\
OUTPUT_FILE=results.json (only needed if ENABLE_OUTPUT_FILE=true, must mount file in docker run to get this output)\
REQUEST_DELAY_SECONDS=1 (only supports integers and adjust acording to needs)