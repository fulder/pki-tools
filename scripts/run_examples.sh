#!/usr/bin/env bash

RED='\033[0;31m'
NC='\033[0m' # No Color

exclude_outputs=(
  "create_csr.py"
  "create_chain.py"
  "create_cert_cross_signed.py"
  "create_cert_self_signed.py"
)

error_flag=0

find "./docs/examples/src" -type f -name "*py" -print0 | while IFS= read -r -d '' file; do
  dir=$(dirname "$file")
  file_name=$(basename "$file")

  echo "Running ${file_name}..."

  out_name="${file_name%.*}.out"
  out_file="${dir}/${out_name}"

  pushd $dir

  if [[ "${exclude_outputs[@]}" =~ "${file_name}" ]]; then
    LOGURU_LEVEL=INFO poetry run python3 "${file_name}" > /dev/null 2>&1
  else
    LOGURU_LEVEL=INFO poetry run python3 "${file_name}" > ${out_name} 2>&1
  fi

  popd

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