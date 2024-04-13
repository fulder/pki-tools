#!/usr/bin/env bash

RED='\033[0;31m'
NC='\033[0m' # No Color

exclude_outputs=(
  "create_csr.py"
  "create_chain.py"
  "create_cert_cross_signed.py"
  "create_cert_self_signed.py"
  "create.py"
  "load_cert_server.py"
)

error_flag=0

declare -A pid_map

while IFS= read -r -d '' file; do
  dir=$(dirname "$file")
  file_name=$(basename "$file")

  echo "Running ${file_name}..."

  out_name="${file_name%.*}.out"
  out_file="${dir}/${out_name}"

  pushd $dir

  if [[ "${exclude_outputs[@]}" =~ "${file_name}" ]]; then
    LOGURU_LEVEL=INFO poetry run python3 "${file_name}" > /dev/null 2>&1 &
  else
    LOGURU_LEVEL=INFO poetry run python3 "${file_name}" > ${out_name} 2>&1 &
  fi

  pid_map[$!]=$out_file

  popd

done < <(find "./docs/examples/src" -type f -name "*py" -print0)

for pid in "${!pid_map[@]}"; do
    wait "$pid"
    err_out=$?
    if [ $err_out -ne 0 ]; then
      outfile=${pid_map[$pid]}
      printf "${RED}Error executing ${outfile}${NC}\n"
      cat "${outfile}"
    fi
    ((error_flag+=$err_out))
done

if [ ${error_flag} -eq 0 ]; then
  echo "Executed successfully"
else
  exit ${error_flag}
fi