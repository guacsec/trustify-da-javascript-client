#!/bin/sh

manifest_file_path="$1"
output_file_path="$2"

printf "Analyzing the stack. Please wait..\n\n"

# Get the directory containing the manifest file
manifest_dir=$(dirname "$manifest_file_path")
manifest_name=$(basename "$manifest_file_path")

# Detect and set the correct yarn version if this is a yarn project
if [ "$manifest_name" = "package.json" ] && [ -f "$manifest_dir/yarn.lock" ]; then
  # Check if packageManager is already declared in package.json
  package_manager=$(jq -r '.packageManager // empty' "$manifest_file_path" 2>/dev/null)
  
  if [ -z "$package_manager" ]; then
    # No packageManager declared, detect based on project files
    if [ -f "$manifest_dir/.yarnrc.yml" ]; then
      # .yarnrc.yml exists = Yarn Berry
      printf "Detected Yarn Berry project (found .yarnrc.yml), using yarn@4.9.1\n"
      export TRUSTIFY_DA_YARN_PATH=/usr/local/bin/yarn-berry
    else
      # No .yarnrc.yml = Yarn Classic
      printf "Detected Yarn Classic project, using yarn@1.22.22\n"
      export TRUSTIFY_DA_YARN_PATH=/usr/local/bin/yarn-classic
    fi
  else
    printf "Using declared packageManager: %s\n" "$package_manager"
  fi
fi

# Getting RHDA stack analysis report using Exhort Javascript CLI.
report=$(trustify-da stack $manifest_file_path 2>error.log)

exit_code=$?

if [ $exit_code != 0 ]
then
  # Read the full error log
  error_log=$(cat error.log 2>/dev/null || echo "")

  # Extract the main error message (first Error: line)
  main_error=$(echo "$error_log" | grep -m1 "^Error:" || echo "Unknown error")

  # Extract cause chain (lines with "cause:" or indented error details)
  cause_chain=$(echo "$error_log" | grep -E "(cause:|Caused by|    at )" | head -20 || echo "")

  # In case of failure save error details into output file.
  jq -n {} | \
  jq --arg exit_code "$exit_code" \
     --arg error "$main_error" \
     --arg stderr "$error_log" \
     '. + {exit_code: $exit_code, error: $error, stderr: $stderr}' > \
  $output_file_path

  # Print detailed error message to console
  printf "\n[ERROR] Trustify Dependency Analytics failed with exit code $exit_code.\n"
  printf "\n%s\n" "$main_error"

  if [ -n "$cause_chain" ]; then
    printf "\nCause chain:\n%s\n" "$cause_chain"
  fi

  # Show full stderr if it contains additional information
  if [ -n "$error_log" ] && [ "$error_log" != "$main_error" ]; then
    printf "\nFull error output:\n"
    printf "=%.0s" {1..50}
    printf "\n%s\n" "$error_log"
    printf "=%.0s" {1..50}
  fi

  exit 1
else
# In case of success print report summary into console
printf "\nTrustify Dependency Analytics Report\n"
printf "=%.0s" {1..50}
printf "\n"
printf "Dependencies\n"
printf "  Total Scanned      :  %s \n" "$(jq -r '.scanned.total' <<< $report)"
printf "  Total Direct       :  %s \n" "$(jq -r '.scanned.direct' <<< $report)"
printf "  Total Transitive   :  %s \n" "$(jq -r '.scanned.transitive' <<< $report)"

providers=$(jq -rc '.providers | keys[] | select(. != "trusted-content")' <<< "$report")
while IFS= read -r provider; do
  [ -z "$provider" ] && continue
  printf "\nProvider: %s\n" "${provider^}"

  provider_status=$(jq -r --arg provider "$provider" '.providers[$provider].status' <<< $report)
  message=$(echo $provider_status | jq -r '.message')
  printf "  Provider Status    :"
  printf "%+40s" $message $'\n'  | sed 's/  */ /g'

  code=$(echo $provider_status | jq -r '.code')
  if [ "$code" -eq 200 ]; then
    sources=$(jq -r --arg provider "$provider" '.providers[$provider].sources | keys[]' <<< "$report")
    while IFS= read -r source; do
      printf "  Source: %s\n" "${source^}"
      printf "    Vulnerabilities\n"
      printf "      Total          :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.total' <<< $report)"
      printf "      Direct         :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.direct' <<< $report)"
      printf "      Transitive     :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.transitive' <<< $report)"
      printf "      Critical       :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.critical' <<< $report)"
      printf "      High           :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.high' <<< $report)"
      printf "      Medium         :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.medium' <<< $report)"
      printf "      Low            :  %s \n" "$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.low' <<< $report)"
      remediations_count=$(jq -r --arg provider "$provider" --arg source "$source" '.providers[$provider].sources[$source].summary.remediations // 0' <<< $report)
      printf "    Remediations     :  %s \n" "$remediations_count"
      if [ "$remediations_count" -gt 0 ] 2>/dev/null; then
        jq -r --arg provider "$provider" --arg source "$source" '
          [.providers[$provider].sources[$source].dependencies[] |
            . as $dep |
            [(.issues // [])[] | select(.remediation != null) |
              if .remediation.trustedContent.ref != null then
                {ref: $dep.ref, target: .remediation.trustedContent.ref, type: "trustedContent", cves: ((.cves // [.id]) | join(", "))}
              elif .remediation.fixedIn != null then
                {ref: $dep.ref, target: (.remediation.fixedIn | join(", ")), type: "fixedIn", cves: ((.cves // [.id]) | join(", "))}
              else
                empty
              end
            ] + [(.transitive // [])[] | . as $t |
              (.issues // [])[] | select(.remediation != null) |
              if .remediation.trustedContent.ref != null then
                {ref: $t.ref, target: .remediation.trustedContent.ref, type: "trustedContent", cves: ((.cves // [.id]) | join(", "))}
              elif .remediation.fixedIn != null then
                {ref: $t.ref, target: (.remediation.fixedIn | join(", ")), type: "fixedIn", cves: ((.cves // [.id]) | join(", "))}
              else
                empty
              end
            ]
          ] | flatten | unique_by({ref, target}) |
          sort_by(if .type == "trustedContent" then 0 else 1 end) | .[] |
          "      \(.ref)\n        → \(.target)\n        CVEs: \(.cves)"
        ' <<< "$report"
      fi
    done <<< "$sources"

    rec_sources=$(jq -r --arg provider "$provider" '.providers[$provider].recommendations // {} | keys[]' <<< "$report" 2>/dev/null)
    while IFS= read -r rec_source; do
      [ -z "$rec_source" ] && continue
      rec_total=$(jq -r --arg provider "$provider" --arg rs "$rec_source" '.providers[$provider].recommendations[$rs].summary.total // 0' <<< "$report")
      printf "  Recommendations (%s): %s\n" "$rec_source" "$rec_total"
      if [ "$rec_total" -gt 0 ] 2>/dev/null; then
        jq -r --arg provider "$provider" --arg rs "$rec_source" '
          .providers[$provider].recommendations[$rs].dependencies[]? |
          "    \(.ref)\n      → \(.recommendation)"
        ' <<< "$report"
      fi
    done <<< "$rec_sources"
  fi
done <<< "$providers"
printf "=%.0s" {1..50}

  # Save report along with exit code into output file.
  jq -n {} | \
  jq --slurpfile report <(echo "$report") '. + {report: $report[0]}' | \
  jq --arg exit_code "$exit_code" '. + {exit_code: $exit_code}' > \
  $output_file_path

  printf "\nFull report is saved into file: $output_file_path"
  printf "\nTask is completed.\n"
fi
