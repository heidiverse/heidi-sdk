#!/usr/bin/env bash
set -euo pipefail

mode=${1:?"mode required (build|publish)"}
tasks=${2:?"tasks required"}
enable_ios=${3:?"enableIosTargets required (true|false)"}

if [[ -z "${MAVEN_SIGNING_KEY_ARMOR_ASC:-}" ]]; then
  echo "MAVEN_SIGNING_KEY_ARMOR_ASC is required" >&2
  exit 1
fi

if [[ -z "${MAVEN_SIGNING_KEY_PASSPHRASE:-}" ]]; then
  echo "MAVEN_SIGNING_KEY_PASSPHRASE is required" >&2
  exit 1
fi

if [[ -z "${MAVEN_SIGNING_KEY_ID:-}" ]]; then
  echo "MAVEN_SIGNING_KEY_ID is required" >&2
  exit 1
fi

if [[ -z "${MAVEN_CENTRAL_USERNAME:-}" ]]; then
  echo "MAVEN_CENTRAL_USERNAME is required" >&2
  exit 1
fi

if [[ -z "${MAVEN_CENTRAL_PASSWORD:-}" ]]; then
  echo "MAVEN_CENTRAL_PASSWORD is required" >&2
  exit 1
fi

echo "$MAVEN_SIGNING_KEY_ARMOR_ASC" > ./signingkey.asc
gpg --quiet --output "$GITHUB_WORKSPACE/signingkey.gpg" --dearmor ./signingkey.asc

extra_props=(
  "-PenableIosTargets=${enable_ios}"
  "-Psigning.secretKeyRingFile=$GITHUB_WORKSPACE/signingkey.gpg"
  "-Psigning.password=${MAVEN_SIGNING_KEY_PASSPHRASE}"
  "-Psigning.keyId=${MAVEN_SIGNING_KEY_ID}"
  "-PmavenCentralUsername=${MAVEN_CENTRAL_USERNAME}"
  "-PmavenCentralPassword=${MAVEN_CENTRAL_PASSWORD}"
)

if [[ "$mode" == "publish" ]]; then
  if [[ -z "${GITHUB_REF_NAME:-}" ]]; then
    echo "GITHUB_REF_NAME is required for publish" >&2
    exit 1
  fi
  extra_props+=(
    "-PgithubRefName=${GITHUB_REF_NAME}"
    "-PreleaseBuild=true"
  )
fi

./gradlew buildBindings ${tasks} --console=plain "${extra_props[@]}"
