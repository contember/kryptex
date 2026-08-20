#!/usr/bin/env bash
set -euo pipefail

readonly WRANGLER_VERSION="4.124.0"
readonly BUCKET_NAME="kryptex-ciphertext"
readonly RULE_NAME="kryptex-v1-candidate-backstop"
readonly RULE_PREFIX="v1/candidates/"
readonly EXPIRE_DAYS="14"
readonly EXPECTED_ACTION="Expire objects after 14 days"
readonly EXPECTED_DEV_URL_STATUS="Public access via the r2.dev URL is disabled."
readonly EXPECTED_DOMAIN_STATUS="There are no custom domains connected to this bucket."
readonly CONFIG_PATH="packages/worker/wrangler.jsonc"

usage() {
  printf 'Usage: %s apply|verify\n' "$0" >&2
}

case "${1:-}" in
  apply)
    bunx --bun "wrangler@${WRANGLER_VERSION}" r2 bucket lifecycle add \
      "${BUCKET_NAME}" \
      "${RULE_NAME}" \
      "${RULE_PREFIX}" \
      --expire-days "${EXPIRE_DAYS}" \
      --force \
      --config "${CONFIG_PATH}"
    ;;
  verify)
    lifecycle_output="$(bunx --bun "wrangler@${WRANGLER_VERSION}" r2 bucket lifecycle list \
      "${BUCKET_NAME}" \
      --config "${CONFIG_PATH}")"
    printf '%s\n' "${lifecycle_output}"
    awk \
      -v name="${RULE_NAME}" \
      -v prefix="${RULE_PREFIX}" \
      -v action="${EXPECTED_ACTION}" \
      'function field_equals(record, label, expected, lines, line_count, line_number, line) {
         line_count = split(record, lines, "\n")
         for (line_number = 1; line_number <= line_count; line_number += 1) {
           line = lines[line_number]
           if (line ~ "^[[:space:]]*" label ":[[:space:]]*") {
             sub("^[[:space:]]*" label ":[[:space:]]*", "", line)
             if (line == expected) {
               return 1
             }
           }
         }
         return 0
       }
       BEGIN { RS = "" }
       field_equals($0, "name", name) && field_equals($0, "enabled", "Yes") && field_equals($0, "prefix", prefix) && field_equals($0, "action", action) { valid = 1 }
       END { exit valid == 1 ? 0 : 1 }' <<<"${lifecycle_output}" || {
      printf 'Lifecycle rule must be enabled with prefix %s and action %s: %s\n' \
        "${RULE_PREFIX}" "${EXPECTED_ACTION}" "${RULE_NAME}" >&2
      exit 1
    }

    dev_url_output="$(bunx --bun "wrangler@${WRANGLER_VERSION}" r2 bucket dev-url get \
      "${BUCKET_NAME}" \
      --config "${CONFIG_PATH}")"
    printf '%s\n' "${dev_url_output}"
    grep -Fxq -- "${EXPECTED_DEV_URL_STATUS}" <<<"${dev_url_output}" || {
      printf 'R2 development URL must be disabled.\n' >&2
      exit 1
    }

    domain_output="$(bunx --bun "wrangler@${WRANGLER_VERSION}" r2 bucket domain list \
      "${BUCKET_NAME}" \
      --config "${CONFIG_PATH}")"
    printf '%s\n' "${domain_output}"
    grep -Fxq -- "${EXPECTED_DOMAIN_STATUS}" <<<"${domain_output}" || {
      printf 'R2 bucket must have no custom domains.\n' >&2
      exit 1
    }
    ;;
  *)
    usage
    exit 64
    ;;
esac
