#!/usr/bin/env bash

RED='\033[0;31m'
NC='\033[0m' # No Color

cd ./docs/examples/src

exclude_outputs=("create_cert.py" "create_csr.py")

error_flag=0
for file in *.py; do
  echo "Running $file..."

  out_file="${file%.*}.out"

  if [[ "${exclude_outputs[@]}" =~ "${file}" ]]; then
    LOGURU_LEVEL=INFO poetry run python3 "$file" 2>&1
  else
    LOGURU_LEVEL=INFO poetry run python3 "$file" > ${out_file} 2>&1
  fi

  # Check the exit code of the Python command
  if [ $? -eq 0 ]; then
    echo "$file executed successfully"
  else
    printf "${RED}Error executing $file${NC}\n"
    cat "${out_file}"
    error_flag=1
  fi
done

exit $error_flag