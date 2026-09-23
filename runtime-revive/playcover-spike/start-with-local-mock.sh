#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
MOCK_HOST="127.0.0.1"
MOCK_PORT="3001"
MOCK_SCRIPT="$ROOT_DIR/runtime-revive/playcover-spike/mock-server/server.py"
MOCK_SCRIPT_RELATIVE="${MOCK_SCRIPT#"$ROOT_DIR"/}"
MOCK_LOG_DIR="$ROOT_DIR/runtime-revive/playcover-spike/mock-server/logs"
DEFAULT_LAUNCH_SCRIPT="$ROOT_DIR/runtime-revive/playcover-spike/run-network-redirect-from-launch.sh"
LAUNCH_SCRIPT="${PLAYCOVER_LAUNCH_SCRIPT:-$DEFAULT_LAUNCH_SCRIPT}"
REQUIRE_OWN_MOCK="${PLAYCOVER_REQUIRE_OWN_MOCK:-0}"
REQUIRE_TARGET_STOPPED_ON_EXIT="${PLAYCOVER_REQUIRE_TARGET_STOPPED_ON_EXIT:-1}"
CAPTURE_LOCK_DIR="${TMPDIR:-/tmp}/archercat-playcover-capture-mock.lock"
source "$ROOT_DIR/runtime-revive/playcover-spike/playcover-runtime-env.sh"
set_uv_run_cmd "$ROOT_DIR"
prepare_playcover_profile_fixture
start_new_playcover_batch_token

STARTED_MOCK_PID=""
STARTED_MOCK_START_TOKEN=""
OWNED_MOCK_LISTENER_PIDS=""
OWNED_MOCK_LISTENER_RECORDS=""
OWNS_CAPTURE_LOCK=0
CAPTURE_LOCK_ID=""
CLEANUP_DONE=0
LAUNCHER_PID=""
LAUNCHER_START_TOKEN=""
LAUNCHER_INITIAL_COMMAND=""
CAPTURE_TARGET_PID_FILE=""

mock_is_listening() {
  nc -z "$MOCK_HOST" "$MOCK_PORT" >/dev/null 2>&1
}

process_start_token() {
  local pid="$1"
  ps -p "$pid" -o lstart= 2>/dev/null | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

capture_lock_identity() {
  stat -f '%d:%i' "$CAPTURE_LOCK_DIR" 2>/dev/null || true
}

acquire_capture_lock() {
  if [[ "$REQUIRE_OWN_MOCK" != "1" ]]; then
    return
  fi

  if ! mkdir "$CAPTURE_LOCK_DIR" 2>/dev/null; then
    local owner=""
    if [[ -f "$CAPTURE_LOCK_DIR/owner-pid" && ! -L "$CAPTURE_LOCK_DIR/owner-pid" ]]; then
      owner="$(tr -d '[:space:]' < "$CAPTURE_LOCK_DIR/owner-pid")"
    fi
    echo "Refusing to delete or replace the existing controlled-capture lock: $CAPTURE_LOCK_DIR" >&2
    if [[ -n "$owner" ]]; then
      echo "Recorded owner pid: $owner" >&2
    fi
    echo "Removing this lock requires explicit user authorization after an ownership audit." >&2
    exit 1
  fi

  printf '%s\n' "$$" > "$CAPTURE_LOCK_DIR/owner-pid"
  CAPTURE_LOCK_ID="$(capture_lock_identity)"
  if [[ -z "$CAPTURE_LOCK_ID" ]]; then
    echo "Could not record the identity of the newly created capture lock." >&2
    exit 1
  fi
  OWNS_CAPTURE_LOCK=1
}

refuse_existing_mock_listener() {
  if ! mock_is_listening; then
    return
  fi
  if ! command -v lsof >/dev/null 2>&1; then
    echo "lsof is required to verify ownership of the existing mock listener." >&2
    exit 1
  fi

  local listener_pids
  listener_pids="$(lsof -nP -iTCP:"$MOCK_PORT" -sTCP:LISTEN -t 2>/dev/null || true)"
  if [[ -z "$listener_pids" ]]; then
    if mock_is_listening; then
      echo "Could not identify the process listening on $MOCK_HOST:$MOCK_PORT." >&2
      exit 1
    fi
    return
  fi

  echo "Refusing to stop or reuse the existing listener on $MOCK_HOST:$MOCK_PORT." >&2
  local pid
  local command
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    echo "  pid=$pid command=$command" >&2
  done <<< "$listener_pids"
  echo "Stopping a listener from another batch requires explicit user authorization for its exact identity." >&2
  exit 1
}

process_is_descendant_of() {
  local pid="$1"
  local ancestor="$2"
  local parent

  while [[ "$pid" =~ ^[0-9]+$ ]] && [[ "$pid" -gt 1 ]]; do
    if [[ "$pid" == "$ancestor" ]]; then
      return 0
    fi
    parent="$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d '[:space:]')"
    if [[ -z "$parent" || "$parent" == "$pid" ]]; then
      break
    fi
    pid="$parent"
  done
  return 1
}

verify_owned_mock_listener() {
  if [[ "$REQUIRE_OWN_MOCK" != "1" ]]; then
    return
  fi
  if ! command -v lsof >/dev/null 2>&1; then
    echo "lsof is required to verify ownership of the local mock listener." >&2
    exit 1
  fi

  local listener_pids
  listener_pids="$(lsof -nP -iTCP:"$MOCK_PORT" -sTCP:LISTEN -t 2>/dev/null || true)"
  if [[ -z "$listener_pids" ]]; then
    echo "Could not identify the owned mock listener on $MOCK_HOST:$MOCK_PORT." >&2
    exit 1
  fi

  local pid
  local command
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    if [[ "$command" != *"$MOCK_SCRIPT"* && "$command" != *"$MOCK_SCRIPT_RELATIVE"* ]]; then
      echo "Listener pid=$pid does not run the project mock: $command" >&2
      exit 1
    fi
    if ! process_is_descendant_of "$pid" "$STARTED_MOCK_PID"; then
      echo "Listener pid=$pid is not owned by started mock pid=$STARTED_MOCK_PID." >&2
      exit 1
    fi
    local start_token
    start_token="$(process_start_token "$pid")"
    if [[ -z "$start_token" ]]; then
      echo "Could not record start identity for owned mock listener pid=$pid." >&2
      exit 1
    fi
    OWNED_MOCK_LISTENER_RECORDS+="$pid|$start_token"$'\n'
  done <<< "$listener_pids"
  OWNED_MOCK_LISTENER_PIDS="$listener_pids"
}

target_stopped_before_cleanup() {
  if [[ "$REQUIRE_TARGET_STOPPED_ON_EXIT" != "1" ]]; then
    return 0
  fi
  if [[ -z "$CAPTURE_TARGET_PID_FILE" || ! -e "$CAPTURE_TARGET_PID_FILE" ]]; then
    local observed_pids
    local observed_pid
    if ! observed_pids="$(playcover_archercat_target_pids)"; then
      echo "Could not verify that ArcherCat stopped; preserving the mock and capture lock." >&2
      return 1
    fi
    if [[ -z "$observed_pids" ]]; then
      return 0
    fi
    echo "An ArcherCat process is still alive without a current-batch target record; preserving the mock." >&2
    while IFS= read -r observed_pid; do
      [[ -n "$observed_pid" ]] || continue
      echo "  pid=$observed_pid command=$(ps -p "$observed_pid" -o command= 2>/dev/null || true)" >&2
    done <<< "$observed_pids"
    return 1
  fi
  if [[ ! -f "$CAPTURE_TARGET_PID_FILE" || -L "$CAPTURE_TARGET_PID_FILE" ]]; then
    echo "Refusing target cleanup because the batch target record is not a regular owned file." >&2
    return 1
  fi

  local target_pid
  local state
  target_pid="$(tr -d '[:space:]' < "$CAPTURE_TARGET_PID_FILE")"
  if [[ ! "$target_pid" =~ ^[0-9]+$ ]]; then
    echo "Refusing target cleanup because the batch target record is invalid: $target_pid" >&2
    return 1
  fi
  state="$(ps -p "$target_pid" -o stat= 2>/dev/null | tr -d '[:space:]')"
  if [[ -z "$state" || "$state" == Z* ]]; then
    return 0
  fi

  echo "The controlled target pid=$target_pid is still alive; preserving its mock and capture lock." >&2
  echo "The outer wrapper will not signal it. Exact-identity termination requires explicit authorization." >&2
  return 1
}

stop_owned_mock_process() {
  local pid="$1"
  local expected_start_token="$2"
  local label="$3"
  local command
  local actual_start_token

  command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  if [[ -z "$command" ]]; then
    return 0
  fi
  actual_start_token="$(process_start_token "$pid")"
  if [[ "$actual_start_token" != "$expected_start_token" ]] ||
     [[ "$command" != *"$MOCK_SCRIPT"* && "$command" != *"$MOCK_SCRIPT_RELATIVE"* ]]; then
    echo "Refusing to stop $label pid=$pid because its start identity or command changed: $command" >&2
    return 1
  fi

  echo "Stopping $label pid=$pid"
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      return 0
    fi
    sleep 0.05
  done
  echo "Timed out waiting for $label pid=$pid; preserving the batch lock." >&2
  return 1
}

release_owned_capture_lock() {
  if [[ "$OWNS_CAPTURE_LOCK" != "1" ]]; then
    return 0
  fi
  local current_lock_id
  local owner
  local entry
  current_lock_id="$(capture_lock_identity)"
  if [[ -z "$current_lock_id" || "$current_lock_id" != "$CAPTURE_LOCK_ID" ]]; then
    echo "Refusing to remove capture lock because its directory identity changed." >&2
    return 1
  fi
  if [[ ! -f "$CAPTURE_LOCK_DIR/owner-pid" || -L "$CAPTURE_LOCK_DIR/owner-pid" ]]; then
    echo "Refusing to remove capture lock because its owner record changed type." >&2
    return 1
  fi
  owner="$(tr -d '[:space:]' < "$CAPTURE_LOCK_DIR/owner-pid")"
  if [[ "$owner" != "$$" ]]; then
    echo "Refusing to remove capture lock because owner pid changed from $$ to $owner." >&2
    return 1
  fi
  for entry in "$CAPTURE_LOCK_DIR"/*; do
    [[ -e "$entry" || -L "$entry" ]] || continue
    case "${entry##*/}" in
      owner-pid|target-pid)
        if [[ ! -f "$entry" || -L "$entry" ]]; then
          echo "Refusing to remove capture lock because ${entry##*/} is not a regular owned file." >&2
          return 1
        fi
        ;;
      *)
        echo "Refusing to remove capture lock with unexpected entry: $entry" >&2
        return 1
        ;;
    esac
  done

  if [[ -n "$CAPTURE_TARGET_PID_FILE" && -f "$CAPTURE_TARGET_PID_FILE" ]]; then
    rm -f "$CAPTURE_TARGET_PID_FILE"
  fi
  rm -f "$CAPTURE_LOCK_DIR/owner-pid"
  if ! rmdir "$CAPTURE_LOCK_DIR"; then
    echo "Could not release the verified current-batch capture lock." >&2
    return 1
  fi
}

cleanup() {
  local original_status=$?
  if [[ "$CLEANUP_DONE" == "1" ]]; then
    return
  fi
  CLEANUP_DONE=1

  if ! target_stopped_before_cleanup; then
    if [[ "$original_status" == "0" ]]; then
      trap - EXIT
      exit 1
    fi
    return
  fi

  local cleanup_failed=0
  if [[ -n "$STARTED_MOCK_PID" && -n "$STARTED_MOCK_START_TOKEN" ]]; then
    stop_owned_mock_process "$STARTED_MOCK_PID" "$STARTED_MOCK_START_TOKEN" "owned mock launcher" || cleanup_failed=1
  fi
  local listener_record
  local listener_pid
  local listener_start_token
  while IFS= read -r listener_record; do
    [[ -n "$listener_record" ]] || continue
    listener_pid="${listener_record%%|*}"
    listener_start_token="${listener_record#*|}"
    stop_owned_mock_process "$listener_pid" "$listener_start_token" "owned mock listener" || cleanup_failed=1
  done <<< "$OWNED_MOCK_LISTENER_RECORDS"
  if [[ "$cleanup_failed" == "0" ]]; then
    release_owned_capture_lock || cleanup_failed=1
  fi
  if [[ "$cleanup_failed" != "0" && "$original_status" == "0" ]]; then
    trap - EXIT
    exit 1
  fi
}

forward_signal_and_exit() {
  local signal_name="$1"
  local exit_code="$2"
  if [[ -n "$LAUNCHER_PID" ]] && kill -0 "$LAUNCHER_PID" 2>/dev/null; then
    if ! verify_owned_playcover_launcher \
      "$LAUNCHER_PID" \
      "$LAUNCHER_START_TOKEN" \
      "$PLAYCOVER_BATCH_TOKEN" \
      "$$"; then
      echo "Refusing to signal launcher pid=$LAUNCHER_PID because its start identity or batch token changed." >&2
    else
      kill -s "$signal_name" "$LAUNCHER_PID" 2>/dev/null || true
      wait "$LAUNCHER_PID" 2>/dev/null || true
    fi
  fi
  exit "$exit_code"
}

trap cleanup EXIT
trap 'forward_signal_and_exit INT 130' INT
trap 'forward_signal_and_exit TERM 143' TERM

if [[ ! -f "$MOCK_SCRIPT" ]]; then
  echo "Mock server script not found: $MOCK_SCRIPT" >&2
  exit 1
fi

if [[ ! -x "$LAUNCH_SCRIPT" ]]; then
  echo "Launch script not executable: $LAUNCH_SCRIPT" >&2
  exit 1
fi

refuse_existing_archercat_targets
if [[ "$REQUIRE_OWN_MOCK" == "1" ]]; then
  refuse_existing_mock_listener
fi

acquire_capture_lock

if [[ "$REQUIRE_OWN_MOCK" == "1" ]]; then
  CAPTURE_TARGET_PID_FILE="$CAPTURE_LOCK_DIR/target-pid"
  export PLAYCOVER_CAPTURE_TARGET_PID_FILE="$CAPTURE_TARGET_PID_FILE"
fi

mkdir -p "$MOCK_LOG_DIR"

if [[ "$REQUIRE_OWN_MOCK" == "1" ]] && mock_is_listening; then
  echo "Owned mock mode cannot reuse an existing listener on $MOCK_HOST:$MOCK_PORT." >&2
  exit 1
elif mock_is_listening; then
  echo "Reusing existing local mock server on $MOCK_HOST:$MOCK_PORT"
else
  require_uv_runtime "$ROOT_DIR"

  STAMP="$(date '+%Y%m%d-%H%M%S')"
  MOCK_LOG_FILE="$MOCK_LOG_DIR/mock-$STAMP.jsonl"
  reserve_new_output_file "$MOCK_LOG_FILE" "mock log"
  echo "Starting local mock server on $MOCK_HOST:$MOCK_PORT"
  echo "Writing mock JSONL log to $MOCK_LOG_FILE"
  "${UV_RUN[@]}" python "$MOCK_SCRIPT" \
    --host "$MOCK_HOST" \
    --port "$MOCK_PORT" \
    --log "$MOCK_LOG_FILE" &
  STARTED_MOCK_PID="$!"
  STARTED_MOCK_START_TOKEN="$(process_start_token "$STARTED_MOCK_PID")"
  if [[ -z "$STARTED_MOCK_START_TOKEN" ]]; then
    echo "Could not record the owned mock launch identity." >&2
    exit 1
  fi

  for _ in $(seq 1 100); do
    if mock_is_listening; then
      break
    fi
    if ! kill -0 "$STARTED_MOCK_PID" 2>/dev/null; then
      wait "$STARTED_MOCK_PID" 2>/dev/null || true
      echo "Local mock server exited before accepting connections." >&2
      exit 1
    fi
    sleep 0.05
  done

  if ! mock_is_listening; then
    echo "Timed out waiting for local mock server on $MOCK_HOST:$MOCK_PORT" >&2
    exit 1
  fi
  if ! kill -0 "$STARTED_MOCK_PID" 2>/dev/null; then
    wait "$STARTED_MOCK_PID" 2>/dev/null || true
    echo "Local mock launcher exited after another process claimed $MOCK_HOST:$MOCK_PORT." >&2
    exit 1
  fi
  verify_owned_mock_listener
fi

if ! mock_is_listening; then
  echo "Local mock server is not listening on $MOCK_HOST:$MOCK_PORT before launch." >&2
  exit 1
fi

echo "Launching ArcherCat through Frida network redirect."
echo "Do not start the game directly from PlayCover for this mock-backed flow."
echo "PlayCover batch token: $PLAYCOVER_BATCH_TOKEN"
"$LAUNCH_SCRIPT" &
LAUNCHER_PID="$!"
LAUNCHER_START_TOKEN="$(process_start_token "$LAUNCHER_PID")"
LAUNCHER_INITIAL_COMMAND="$(ps -p "$LAUNCHER_PID" -o command= 2>/dev/null || true)"
if [[ -z "$LAUNCHER_START_TOKEN" || -z "$LAUNCHER_INITIAL_COMMAND" || "$LAUNCHER_INITIAL_COMMAND" != *"$LAUNCH_SCRIPT"* ]]; then
  echo "Could not record the owned launcher identity." >&2
  exit 1
fi
LAUNCH_STATUS=0
if wait "$LAUNCHER_PID"; then
  LAUNCH_STATUS=0
else
  LAUNCH_STATUS="$?"
fi
LAUNCHER_PID=""
LAUNCHER_START_TOKEN=""
LAUNCHER_INITIAL_COMMAND=""
exit "$LAUNCH_STATUS"
