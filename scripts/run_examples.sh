#!/usr/bin/env bash

RED='\033[0;31m'
NC='\033[0m' # No Color

cd ./docs/examples/src

error_flag=0
for file in *.py; do
  echo "Running $file..."
  output=$(PYTHONPATH=. python "$file" 2>&1)

  # Check the exit code of the Python command
  if [ $? -eq 0 ]; then
    echo "$file executed successfully"
  else
    printf "${RED}Error executing $file${NC}\n"
    echo $output
  error_flag=1
  fi
done

exit $error_flag