#!/usr/bin/env bash
# tools/run-sim.sh
# Builds the project (if needed) and runs the two simulation binaries,
# saving stdout/stderr into timestamped log files under logs/.
#
# Usage:
#   ./tools/run-sim.sh [build]
#   ./tools/run-sim.sh auth_scenario
#   ./tools/run-sim.sh uav_data_scenario
#
# By default runs both simulations sequentially.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
NS3_BUILD_DIR="/home/rky_cse/ns-3.46/build"

mkdir -p "${PROJECT_ROOT}/logs"
timestamp() {
  date +"%Y%m%d-%H%M%S"
}

# Build if requested or if binaries missing
if [[ "${1:-}" == "build" || ! -f "${BUILD_DIR}/auth_scenario" || ! -f "${BUILD_DIR}/uav_data_scenario" ]]; then
  echo "[run-sim] Building project..."
  mkdir -p "${BUILD_DIR}"
  pushd "${BUILD_DIR}" >/dev/null
  cmake -DNS3_BUILD_DIR="${NS3_BUILD_DIR}" ..
  cmake --build . -- -j"$(nproc)"
  popd >/dev/null
fi

run_one() {
  local bin="$1"
  shift
  local name
  name="$(basename "${bin}")"
  local ts
  ts="$(timestamp)"
  local logfile="${PROJECT_ROOT}/logs/${name}-${ts}.log"
  echo "[run-sim] Running ${name} -> ${logfile}"
  "${BUILD_DIR}/${bin}" "$@" 2>&1 | tee "${logfile}"
}

case "${1:-}" in
  auth_scenario)
    run_one "auth_scenario"
    exit 0
    ;;
  uav_data_scenario)
    run_one "uav_data_scenario"
    exit 0
    ;;
  build)
    echo "[run-sim] Build finished."
    exit 0
    ;;
  "" )
    # run both
    run_one "auth_scenario"
    run_one "uav_data_scenario"
    ;;
  *)
    echo "Usage: $0 [build|auth_scenario|uav_data_scenario]"
    exit 1
    ;;
esac
