#!/bin/sh

manifest_file_path="$1"
output_file_path="$2"

printf "Analyzing the stack. Please wait..\n\n"

# Getting RHDA stack analysis report using Exhort Javascript CLI.
report=$(trustify-da-javascript-client stack $manifest_file_path 2>error.log)

exit_code=$?

if [ $exit_code != 0 ]
then
  # In case of failure save only exit code into output file.
  jq -n {} | \
  jq --arg exit_code "$exit_code" '. + {exit_code: $exit_code}' > \
  $output_file_path

  # Print stderr message to console
  error_message=$(sed -n '/^Error:/p' error.log)
  printf "\n[ERROR] Red Hat Dependency Analytics failed with exit code $exit_code.\n$error_message"
  exit 1
else
# In case of success print report summary into console
printf "\nRed Hat Dependency Analytics Report\n"
printf "=%.0s" {1..50}
printf "\n"
printf "Dependencies\n"
printf "  Total Scanned      :  %s \n" "$(jq -r '.scanned.total' <<< $report)"
printf "  Total Direct       :  %s \n" "$(jq -r '.scanned.direct' <<< $report)"
printf "  Total Transitive   :  %s \n" "$(jq -r '.scanned.transitive' <<< $report)"

providers=$(jq -rc '.providers | keys[] | select(. != "trusted-content")' <<< "$report")
for provider in $providers; do
  printf "\nProvider: %s\n" "${provider^}"

  provider_status=$(jq -r --arg provider "$provider" '.providers[$provider].status' <<< $report)
  message=$(echo $provider_status | jq -r '.message')
  printf "  Provider Status    :"
  printf "%+40s" $message $'\n'  | sed 's/  */ /g'

  code=$(echo $provider_status | jq -r '.code')
  if [ "$code" -eq 200 ]; then
    sources=$(jq -r --arg provider "$provider" '.providers[$provider].sources | keys[]' <<< "$report")
    for source in $sources; do
      printf "  Source: %s\n" "${source^}"
      printf "    Vulnerabilities\n"
      printf "      Total          :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.total' <<< $report)"
      printf "      Direct         :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.direct' <<< $report)"
      printf "      Transitive     :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.transitive' <<< $report)"
      printf "      Critical       :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.critical' <<< $report)"
      printf "      High           :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.high' <<< $report)"
      printf "      Medium         :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.medium' <<< $report)"
      printf "      Low            :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.low' <<< $report)"
    done
  fi
done
printf "=%.0s" {1..50}

  # Save report along with exit code into output file.
  jq -n {} | \
  jq --slurpfile report <(echo "$report") '. + {report: $report[0]}' | \
  jq --arg exit_code "$exit_code" '. + {exit_code: $exit_code}' > \
  $output_file_path

  printf "\nFull report is saved into file: $output_file_path"
  printf "\nTask is completed."
fi
