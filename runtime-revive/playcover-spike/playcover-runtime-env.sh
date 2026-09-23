#!/usr/bin/env bash

PLAYCOVER_ARCHERCAT_TARGET_PATTERN='/net.cravemob.archercatfriends.app/ArcherCatXFacebook$'
PLAYCOVER_ARCHERCAT_PROCESS_NAME='ArcherCatXFacebook'
PLAYCOVER_REQUIRED_DYLD_TEXT_PATH='/usr/lib/libSystem.B.dylib'
PLAYCOVER_VMMAP_TIMEOUT_SECONDS='2'

playcover_archercat_target_pids() {
  local output
  local pid
  local status

  if output="$(pgrep -f "$PLAYCOVER_ARCHERCAT_TARGET_PATTERN" 2>&1)"; then
    if [[ -z "$output" ]]; then
      echo "Could not inspect existing ArcherCat processes: pgrep succeeded with empty output." >&2
      return 2
    fi
    while IFS= read -r pid; do
      [[ -n "$pid" ]] || continue
      if [[ ! "$pid" =~ ^[1-9][0-9]*$ ]]; then
        echo "Could not inspect existing ArcherCat processes: pgrep returned malformed output." >&2
        printf '%s\n' "$output" >&2
        return 2
      fi
    done <<< "$output"
    printf '%s\n' "$output"
    return 0
  else
    status="$?"
  fi

  if [[ "$status" == "1" && -z "$output" ]]; then
    return 0
  fi
  echo "Could not inspect existing ArcherCat processes with pgrep (status=$status)." >&2
  if [[ -n "$output" ]]; then
    printf '%s\n' "$output" >&2
  fi
  return 2
}

refuse_existing_archercat_targets() {
  local pids
  local pid
  local command

  if ! pids="$(playcover_archercat_target_pids)"; then
    echo "Refusing launch because existing ArcherCat process state is unknown." >&2
    return 2
  fi
  if [[ -z "$pids" ]]; then
    return 0
  fi

  echo "Refusing to terminate or reuse an existing ArcherCat process." >&2
  while IFS= read -r pid; do
    [[ -n "$pid" ]] || continue
    command="$(ps -p "$pid" -o command= 2>/dev/null || true)"
    echo "  pid=$pid command=$command" >&2
  done <<< "$pids"
  echo "Stopping an existing process requires explicit user authorization for that exact identity." >&2
  return 1
}

playcover_single_archercat_target_pid() {
  local pids
  local count

  if ! pids="$(playcover_archercat_target_pids)"; then
    echo "Could not select an ArcherCat target because process enumeration failed." >&2
    return 2
  fi
  if [[ -z "$pids" ]]; then
    return 1
  fi
  count="$(printf '%s\n' "$pids" | awk 'NF { count += 1 } END { print count + 0 }')"
  if [[ "$count" != "1" ]]; then
    echo "Expected exactly one newly launched ArcherCat process; found $count." >&2
    return 2
  fi
  printf '%s\n' "$pids"
}

playcover_process_image_path() {
  local pid="$1"

  lsof -a -p "$pid" -d txt -Fn 2>/dev/null |
    awk '/^n/ { sub(/^n/, ""); print; exit }' || true
}

playcover_process_has_required_dyld_text() {
  local pid="$1"
  local vmmap_output
  local vmmap_status
  local perl_path
  local timeout_seconds="${PLAYCOVER_VMMAP_TIMEOUT_SECONDS:-}"

  if ! command -v vmmap >/dev/null 2>&1; then
    echo "vmmap is required to verify PlayCover dyld readiness." >&2
    return 2
  fi
  if [[ ! "$timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
    echo "PLAYCOVER_VMMAP_TIMEOUT_SECONDS must be a positive integer." >&2
    return 2
  fi
  perl_path="$(command -v perl 2>/dev/null || true)"
  if [[ -z "$perl_path" ]]; then
    echo "perl is required to bound the PlayCover vmmap readiness probe." >&2
    return 2
  fi
  if vmmap_output="$({
    "$perl_path" -e '
      my $seconds = shift @ARGV;
      my $child = fork();
      die "fork failed\\n" unless defined $child;
      if ($child == 0) {
        require POSIX;
        POSIX::setsid() or exit 125;
        exec @ARGV or exit 127;
      }
      $SIG{ALRM} = sub {
        kill "KILL", -$child;
        waitpid($child, 0);
        exit 124;
      };
      alarm $seconds;
      waitpid($child, 0);
      alarm 0;
      my $status = $?;
      exit(($status & 127) ? 128 + ($status & 127) : ($status >> 8));
    ' "$timeout_seconds" vmmap -wide "$pid"
  } 2>/dev/null)"; then
    :
  else
    vmmap_status="$?"
    if [[ "$vmmap_status" == "124" ]]; then
      echo "vmmap timed out after ${timeout_seconds}s while checking PlayCover dyld readiness." >&2
      return 2
    fi
    return 1
  fi
  printf '%s\n' "$vmmap_output" |
    awk -v required="$PLAYCOVER_REQUIRED_DYLD_TEXT_PATH" '
      $1 == "__TEXT" && $NF == required { found = 1 }
      END { exit(found ? 0 : 1) }
    '
}

reserve_new_output_file() {
  local path="$1"
  local label="$2"

  if [[ -e "$path" || -L "$path" ]]; then
    echo "Refusing to overwrite existing $label: $path" >&2
    return 1
  fi
  if ! (set -o noclobber; : > "$path"); then
    echo "Could not create $label exclusively: $path" >&2
    return 1
  fi
}

start_new_playcover_batch_token() {
  if ! command -v uuidgen >/dev/null 2>&1; then
    echo "uuidgen is required to create a PlayCover batch identity." >&2
    return 1
  fi
  PLAYCOVER_BATCH_TOKEN="$(uuidgen | tr '[:lower:]' '[:upper:]')"
  export PLAYCOVER_BATCH_TOKEN
}

prepare_playcover_batch_token() {
  if [[ -z "${PLAYCOVER_BATCH_TOKEN:-}" ]]; then
    start_new_playcover_batch_token
  fi
  if [[ ! "$PLAYCOVER_BATCH_TOKEN" =~ ^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$ ]]; then
    echo "PLAYCOVER_BATCH_TOKEN must be an uppercase UUID." >&2
    return 1
  fi
  export PLAYCOVER_BATCH_TOKEN
}

require_existing_playcover_batch_token() {
  if [[ -z "${PLAYCOVER_BATCH_TOKEN:-}" ]]; then
    echo "PLAYCOVER_BATCH_TOKEN is required; use the token printed by the owning launcher." >&2
    return 1
  fi
  prepare_playcover_batch_token
}

playcover_process_has_environment_assignment() {
  local pid="$1"
  local name="$2"
  local expected_value="$3"
  local process_environment

  process_environment="$(ps eww -p "$pid" -o command= 2>/dev/null || true)"
  [[ " $process_environment " == *" $name=$expected_value "* ]]
}

playcover_process_descendant_pids() {
  local root_pid="$1"
  local frontier="$root_pid"
  local next_frontier
  local parent_pid
  local child_pid
  local children

  while [[ -n "$frontier" ]]; do
    next_frontier=""
    for parent_pid in $frontier; do
      children="$(pgrep -P "$parent_pid" 2>/dev/null || true)"
      for child_pid in $children; do
        [[ "$child_pid" =~ ^[0-9]+$ ]] || continue
        printf '%s\n' "$child_pid"
        next_frontier+=" $child_pid"
      done
    done
    frontier="$next_frontier"
  done
}

playcover_descendant_has_batch_token() {
  local launcher_pid="$1"
  local expected_batch_token="$2"
  local descendant_pid

  while IFS= read -r descendant_pid; do
    [[ -n "$descendant_pid" ]] || continue
    if playcover_process_has_environment_assignment \
      "$descendant_pid" \
      "PLAYCOVER_BATCH_TOKEN" \
      "$expected_batch_token"; then
      return 0
    fi
  done < <(playcover_process_descendant_pids "$launcher_pid")
  return 1
}

verify_owned_playcover_launcher() {
  local pid="$1"
  local expected_start_token="$2"
  local expected_batch_token="$3"
  local expected_owner_pid="${4:-}"
  local actual_start_token
  local actual_parent_pid
  local state

  if [[ ! "$pid" =~ ^[0-9]+$ ]] || [[ -z "$expected_start_token" ]]; then
    return 1
  fi
  if [[ ! "$expected_batch_token" =~ ^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$ ]]; then
    return 1
  fi
  state="$(ps -p "$pid" -o stat= 2>/dev/null | tr -d '[:space:]')"
  if [[ -z "$state" || "$state" == Z* ]]; then
    return 1
  fi
  actual_start_token="$(
    ps -p "$pid" -o lstart= 2>/dev/null |
      sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
  )"
  if [[ "$actual_start_token" != "$expected_start_token" ]]; then
    return 1
  fi
  if playcover_process_has_environment_assignment \
    "$pid" \
    "PLAYCOVER_BATCH_TOKEN" \
    "$expected_batch_token"; then
    return 0
  fi
  if [[ ! "$expected_owner_pid" =~ ^[1-9][0-9]*$ ]]; then
    return 1
  fi
  actual_parent_pid="$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d '[:space:]')"
  if [[ "$actual_parent_pid" != "$expected_owner_pid" ]]; then
    return 1
  fi
  playcover_descendant_has_batch_token "$pid" "$expected_batch_token"
}

verify_playcover_batch_target() {
  local pid="$1"
  local dyld_status
  local process_image
  local process_environment

  if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
    echo "Refusing invalid ArcherCat target pid: $pid" >&2
    return 1
  fi
  prepare_playcover_batch_token
  process_image="$(playcover_process_image_path "$pid")"
  if [[ "${process_image##*/}" != "$PLAYCOVER_ARCHERCAT_PROCESS_NAME" ]]; then
    echo "Refusing to claim ArcherCat pid=$pid before its process image is ready: ${process_image:-unavailable}" >&2
    return 1
  fi
  if playcover_process_has_required_dyld_text "$pid"; then
    :
  else
    dyld_status="$?"
    if [[ "$dyld_status" == "2" ]]; then
      return 1
    fi
    echo "Refusing to claim ArcherCat pid=$pid before dyld is ready: missing __TEXT mapping for $PLAYCOVER_REQUIRED_DYLD_TEXT_PATH" >&2
    return 1
  fi
  process_environment="$(ps eww -p "$pid" -o command= 2>/dev/null || true)"
  if [[ " $process_environment " != *" ARCHERCAT_BATCH_TOKEN=$PLAYCOVER_BATCH_TOKEN "* ]]; then
    echo "Refusing to claim ArcherCat pid=$pid because its launch token does not match the current batch." >&2
    return 1
  fi
}

playcover_batch_target_ready() {
  local pid="$1"
  local dyld_status
  local process_image

  if ! command -v lsof >/dev/null 2>&1; then
    echo "lsof is required to verify the live PlayCover process image." >&2
    return 2
  fi
  process_image="$(playcover_process_image_path "$pid")"
  if [[ "${process_image##*/}" != "$PLAYCOVER_ARCHERCAT_PROCESS_NAME" ]]; then
    return 1
  fi
  if playcover_process_has_required_dyld_text "$pid"; then
    :
  else
    dyld_status="$?"
    if [[ "$dyld_status" == "2" ]]; then
      return 2
    fi
    return 1
  fi
  if ! verify_playcover_batch_target "$pid"; then
    return 2
  fi
}

wait_for_playcover_batch_target() {
  local max_polls="${1:-100}"
  local candidate_pid
  local poll
  local status

  if [[ ! "$max_polls" =~ ^[0-9]+$ ]] || [[ "$max_polls" -le 0 ]]; then
    echo "PlayCover target poll count must be a positive integer." >&2
    return 2
  fi
  for poll in $(seq 1 "$max_polls"); do
    if candidate_pid="$(playcover_single_archercat_target_pid)"; then
      if playcover_batch_target_ready "$candidate_pid"; then
        printf '%s\n' "$candidate_pid"
        return 0
      else
        status="$?"
        if [[ "$status" == "2" ]]; then
          return 2
        fi
      fi
    else
      status="$?"
      if [[ "$status" == "2" ]]; then
        return 2
      fi
    fi
    sleep 0.05
  done
  return 1
}

set_uv_run_cmd() {
  local root_dir="$1"
  UV_RUN=(uv run --project "$root_dir" --locked --no-sync)
}

prepare_playcover_hook_mode() {
  PLAYCOVER_HOOK_MODE_NAME="${PLAYCOVER_HOOK_MODE:-full}"
  case "$PLAYCOVER_HOOK_MODE_NAME" in
    full|light|navigation)
      ;;
    *)
      echo "Unsupported PLAYCOVER_HOOK_MODE: $PLAYCOVER_HOOK_MODE_NAME" >&2
      echo "Expected one of: full, light, navigation" >&2
      exit 1
      ;;
  esac
}

require_playcover_positive_integer() {
  local name="$1"
  local value="$2"
  local maximum="${3:-}"

  if [[ ! "$value" =~ ^[0-9]+$ ]] || [[ "$value" -le 0 ]]; then
    echo "$name must be a positive integer." >&2
    exit 1
  fi
  if [[ -n "$maximum" && "$value" -gt "$maximum" ]]; then
    echo "$name must not exceed $maximum." >&2
    exit 1
  fi
}

prepare_playcover_profile_calendar() {
  local current_tick="${PLAYCOVER_PROFILE_CALENDAR_CUR_TICK:-}"

  if [[ -z "$current_tick" ]]; then
    current_tick="$(date '+%s')"
  fi
  if [[ ! "$current_tick" =~ ^[1-9][0-9]*$ ]] || [[ "$current_tick" -le 86400001 ]]; then
    echo "PLAYCOVER_PROFILE_CALENDAR_CUR_TICK must be an integer greater than 86400001." >&2
    exit 1
  fi
  if [[ "$current_tick" -gt 9007199254740991 ]]; then
    echo "PLAYCOVER_PROFILE_CALENDAR_CUR_TICK exceeds the exact JavaScript integer range." >&2
    exit 1
  fi

  # Freeze the launch clock for nested wrappers and make the emitted facts replayable.
  PLAYCOVER_PROFILE_CALENDAR_CUR_TICK="$current_tick"
  PLAYCOVER_PROFILE_CALENDAR_JSON="{\"curTick\":$current_tick,\"lastDailyRewardTick\":0,\"cumulativeDailyRewardCounter\":0}"
  export PLAYCOVER_PROFILE_CALENDAR_CUR_TICK
}

set_playcover_profile_calendar_claimed_today() {
  PLAYCOVER_PROFILE_CALENDAR_JSON="{\"curTick\":$PLAYCOVER_PROFILE_CALENDAR_CUR_TICK,\"lastDailyRewardTick\":$PLAYCOVER_PROFILE_CALENDAR_CUR_TICK,\"cumulativeDailyRewardCounter\":1}"
}

prepare_playcover_capture_duration() {
  PLAYCOVER_CAPTURE_MAX_DURATION_MS_NAME="${PLAYCOVER_CAPTURE_MAX_DURATION_MS:-120000}"
  require_playcover_positive_integer \
    PLAYCOVER_CAPTURE_MAX_DURATION_MS \
    "$PLAYCOVER_CAPTURE_MAX_DURATION_MS_NAME" \
    300000
  export PLAYCOVER_CAPTURE_MAX_DURATION_MS_NAME
}

prepare_playcover_event_observer_profile() {
  PLAYCOVER_CAPTURE_EVENT_OBSERVER_PROFILE_NAME="${PLAYCOVER_CAPTURE_EVENT_OBSERVER_PROFILE-}"
  case "$PLAYCOVER_CAPTURE_EVENT_OBSERVER_PROFILE_NAME" in
    "")
      ;;
    pause_menu_callback_v1|pause_input_route_v1)
      prepare_playcover_hook_mode
      if [[ "$PLAYCOVER_HOOK_MODE_NAME" != "light" ]]; then
        echo "$PLAYCOVER_CAPTURE_EVENT_OBSERVER_PROFILE_NAME requires PLAYCOVER_HOOK_MODE=light." >&2
        exit 1
      fi
      ;;
    *)
      echo "Unsupported PLAYCOVER_CAPTURE_EVENT_OBSERVER_PROFILE: $PLAYCOVER_CAPTURE_EVENT_OBSERVER_PROFILE_NAME" >&2
      echo "Expected empty, pause_menu_callback_v1, or: pause_input_route_v1" >&2
      exit 1
      ;;
  esac
  if [[ "${PLAYCOVER_CAPTURE_FULL_FRAME_SUBJECT_RTTI-}" == "GamePauseWindow" \
    && "$PLAYCOVER_CAPTURE_EVENT_OBSERVER_PROFILE_NAME" != "pause_input_route_v1" ]]; then
    echo "GamePauseWindow full-frame capture requires PLAYCOVER_CAPTURE_EVENT_OBSERVER_PROFILE=pause_input_route_v1; a third blind Pause attempt is forbidden." >&2
    exit 1
  fi
  export PLAYCOVER_CAPTURE_EVENT_OBSERVER_PROFILE_NAME
}

prepare_playcover_dynamic_recorder_profile() {
  PLAYCOVER_CAPTURE_DYNAMIC_RECORDER_PROFILE_NAME="${PLAYCOVER_CAPTURE_DYNAMIC_RECORDER_PROFILE-}"
  PLAYCOVER_CAPTURE_STOP_AFTER_DYNAMIC_RECORDER_COMPLETE_NAME="${PLAYCOVER_CAPTURE_STOP_AFTER_DYNAMIC_RECORDER_COMPLETE-}"
  case "$PLAYCOVER_CAPTURE_DYNAMIC_RECORDER_PROFILE_NAME" in
    "")
      if [[ -n "$PLAYCOVER_CAPTURE_STOP_AFTER_DYNAMIC_RECORDER_COMPLETE_NAME" ]]; then
        echo "PLAYCOVER_CAPTURE_STOP_AFTER_DYNAMIC_RECORDER_COMPLETE requires PLAYCOVER_CAPTURE_DYNAMIC_RECORDER_PROFILE." >&2
        exit 1
      fi
      ;;
    store_arrow_zero_input_v1)
      prepare_playcover_hook_mode
      if [[ "$PLAYCOVER_HOOK_MODE_NAME" != "light" ]]; then
        echo "store_arrow_zero_input_v1 requires PLAYCOVER_HOOK_MODE=light." >&2
        exit 1
      fi
      if [[ -n "${PLAYCOVER_CAPTURE_EVENT_OBSERVER_PROFILE-}" ]]; then
        echo "Dynamic recorder and event observer profiles cannot run together." >&2
        exit 1
      fi
      if [[ "${PLAYCOVER_CAPTURE_FULL_FRAME-0}" != "1" \
        || "${PLAYCOVER_CAPTURE_SNAPSHOT_ROOT_TYPE-}" != "LoadingTargetScene" \
        || "${PLAYCOVER_CAPTURE_FULL_FRAME_SUBJECT_RTTI-}" != "StoreLayer" ]]; then
        echo "store_arrow_zero_input_v1 requires full-frame capture, LoadingTargetScene, and StoreLayer." >&2
        exit 1
      fi
      if [[ -z "$PLAYCOVER_CAPTURE_STOP_AFTER_DYNAMIC_RECORDER_COMPLETE_NAME" ]]; then
        PLAYCOVER_CAPTURE_STOP_AFTER_DYNAMIC_RECORDER_COMPLETE_NAME=1
      fi
      case "$PLAYCOVER_CAPTURE_STOP_AFTER_DYNAMIC_RECORDER_COMPLETE_NAME" in
        1)
          ;;
        *)
          echo "Store dynamic recorder must stop after recorder completion." >&2
          exit 1
          ;;
      esac
      ;;
    *)
      echo "Unsupported PLAYCOVER_CAPTURE_DYNAMIC_RECORDER_PROFILE: $PLAYCOVER_CAPTURE_DYNAMIC_RECORDER_PROFILE_NAME" >&2
      echo "Expected empty or store_arrow_zero_input_v1" >&2
      exit 1
      ;;
  esac
  export PLAYCOVER_CAPTURE_DYNAMIC_RECORDER_PROFILE_NAME
  export PLAYCOVER_CAPTURE_STOP_AFTER_DYNAMIC_RECORDER_COMPLETE_NAME
}

prepare_playcover_label_upload_capture() {
  local root_dir="$1"

  PLAYCOVER_CAPTURE_LABEL_UPLOAD_NAME="${PLAYCOVER_CAPTURE_LABEL_UPLOAD:-0}"
  PLAYCOVER_LABEL_REQUIRED_CURRENT_TARGETS_NAME="${PLAYCOVER_LABEL_REQUIRED_CURRENT_TARGETS:-}"
  PLAYCOVER_LABEL_FONT_RESOLUTION_OBSERVER_NAME="${PLAYCOVER_LABEL_FONT_RESOLUTION_OBSERVER:-0}"
  case "$PLAYCOVER_CAPTURE_LABEL_UPLOAD_NAME" in
    0)
      if [[ -n "$PLAYCOVER_LABEL_REQUIRED_CURRENT_TARGETS_NAME" ]]; then
        echo "PLAYCOVER_LABEL_REQUIRED_CURRENT_TARGETS requires PLAYCOVER_CAPTURE_LABEL_UPLOAD=1." >&2
        exit 1
      fi
      if [[ "$PLAYCOVER_LABEL_FONT_RESOLUTION_OBSERVER_NAME" != "0" ]]; then
        echo "PLAYCOVER_LABEL_FONT_RESOLUTION_OBSERVER requires PLAYCOVER_CAPTURE_LABEL_UPLOAD=1." >&2
        exit 1
      fi
      return 0
      ;;
    1)
      ;;
    *)
      echo "PLAYCOVER_CAPTURE_LABEL_UPLOAD must be 0 or 1." >&2
      exit 1
      ;;
  esac
  case "$PLAYCOVER_LABEL_FONT_RESOLUTION_OBSERVER_NAME" in
    0)
      ;;
    1)
      if [[ -z "$PLAYCOVER_LABEL_REQUIRED_CURRENT_TARGETS_NAME" ]]; then
        echo "PLAYCOVER_LABEL_FONT_RESOLUTION_OBSERVER=1 requires PLAYCOVER_LABEL_REQUIRED_CURRENT_TARGETS." >&2
        exit 1
      fi
      ;;
    *)
      echo "PLAYCOVER_LABEL_FONT_RESOLUTION_OBSERVER must be 0 or 1." >&2
      exit 1
      ;;
  esac

  prepare_playcover_hook_mode
  if [[ "$PLAYCOVER_HOOK_MODE_NAME" != "light" ]]; then
    echo "Label upload capture requires PLAYCOVER_HOOK_MODE=light." >&2
    exit 1
  fi

  PLAYCOVER_LABEL_UPLOAD_SCRIPT_NAME="${PLAYCOVER_LABEL_UPLOAD_SCRIPT:-}"
  PLAYCOVER_LABEL_UPLOAD_OUTPUT_NAME="${PLAYCOVER_LABEL_UPLOAD_OUTPUT:-}"
  if [[ -z "$PLAYCOVER_LABEL_UPLOAD_SCRIPT_NAME" || -z "$PLAYCOVER_LABEL_UPLOAD_OUTPUT_NAME" ]]; then
    echo "PLAYCOVER_LABEL_UPLOAD_SCRIPT and PLAYCOVER_LABEL_UPLOAD_OUTPUT are required together." >&2
    exit 1
  fi
  if [[ ! -f "$PLAYCOVER_LABEL_UPLOAD_SCRIPT_NAME" ]]; then
    echo "Label upload script not found: $PLAYCOVER_LABEL_UPLOAD_SCRIPT_NAME" >&2
    exit 1
  fi
  if [[ -e "$PLAYCOVER_LABEL_UPLOAD_OUTPUT_NAME" || -L "$PLAYCOVER_LABEL_UPLOAD_OUTPUT_NAME" ]]; then
    echo "Refusing to reuse or overwrite label upload output: $PLAYCOVER_LABEL_UPLOAD_OUTPUT_NAME" >&2
    exit 1
  fi

  if [[ -n "$PLAYCOVER_LABEL_REQUIRED_CURRENT_TARGETS_NAME" ]]; then
    local target_error
    if ! target_error="$(
      PYTHONPATH="$root_dir/runtime-revive/playcover-spike/cocos-ui-capture" \
        python3 -c '
import json
import sys
from label_upload_sidecar import validate_required_current_targets

try:
    validate_required_current_targets(json.loads(sys.argv[1]))
except Exception as error:
    raise SystemExit(str(error))
' "$PLAYCOVER_LABEL_REQUIRED_CURRENT_TARGETS_NAME" 2>&1
    )"; then
      echo "PLAYCOVER_LABEL_REQUIRED_CURRENT_TARGETS is invalid: $target_error" >&2
      exit 1
    fi
  fi

  PLAYCOVER_LABEL_READY_TIMEOUT_MS_NAME="${PLAYCOVER_LABEL_READY_TIMEOUT_MS:-5000}"
  PLAYCOVER_LABEL_DRAIN_TIMEOUT_MS_NAME="${PLAYCOVER_LABEL_DRAIN_TIMEOUT_MS:-5000}"
  PLAYCOVER_LABEL_MAX_TEXTURE_BYTES_NAME="${PLAYCOVER_LABEL_MAX_TEXTURE_BYTES:-4194304}"
  PLAYCOVER_LABEL_MAX_TOTAL_BYTES_NAME="${PLAYCOVER_LABEL_MAX_TOTAL_BYTES:-33554432}"
  PLAYCOVER_LABEL_MAX_CAPTURES_NAME="${PLAYCOVER_LABEL_MAX_CAPTURES:-512}"
  PLAYCOVER_LABEL_MAX_WIDTH_NAME="${PLAYCOVER_LABEL_MAX_WIDTH:-4096}"
  PLAYCOVER_LABEL_MAX_HEIGHT_NAME="${PLAYCOVER_LABEL_MAX_HEIGHT:-2048}"

  require_playcover_positive_integer PLAYCOVER_LABEL_READY_TIMEOUT_MS "$PLAYCOVER_LABEL_READY_TIMEOUT_MS_NAME"
  require_playcover_positive_integer PLAYCOVER_LABEL_DRAIN_TIMEOUT_MS "$PLAYCOVER_LABEL_DRAIN_TIMEOUT_MS_NAME"
  require_playcover_positive_integer PLAYCOVER_LABEL_MAX_TEXTURE_BYTES "$PLAYCOVER_LABEL_MAX_TEXTURE_BYTES_NAME" 4194304
  require_playcover_positive_integer PLAYCOVER_LABEL_MAX_TOTAL_BYTES "$PLAYCOVER_LABEL_MAX_TOTAL_BYTES_NAME" 33554432
  require_playcover_positive_integer PLAYCOVER_LABEL_MAX_CAPTURES "$PLAYCOVER_LABEL_MAX_CAPTURES_NAME" 512
  require_playcover_positive_integer PLAYCOVER_LABEL_MAX_WIDTH "$PLAYCOVER_LABEL_MAX_WIDTH_NAME" 4096
  require_playcover_positive_integer PLAYCOVER_LABEL_MAX_HEIGHT "$PLAYCOVER_LABEL_MAX_HEIGHT_NAME" 2048

  export PLAYCOVER_CAPTURE_LABEL_UPLOAD_NAME
  export PLAYCOVER_LABEL_UPLOAD_SCRIPT_NAME
  export PLAYCOVER_LABEL_UPLOAD_OUTPUT_NAME
  export PLAYCOVER_LABEL_REQUIRED_CURRENT_TARGETS_NAME
  export PLAYCOVER_LABEL_FONT_RESOLUTION_OBSERVER_NAME
  export PLAYCOVER_LABEL_READY_TIMEOUT_MS_NAME
  export PLAYCOVER_LABEL_DRAIN_TIMEOUT_MS_NAME
  export PLAYCOVER_LABEL_MAX_TEXTURE_BYTES_NAME
  export PLAYCOVER_LABEL_MAX_TOTAL_BYTES_NAME
  export PLAYCOVER_LABEL_MAX_CAPTURES_NAME
  export PLAYCOVER_LABEL_MAX_WIDTH_NAME
  export PLAYCOVER_LABEL_MAX_HEIGHT_NAME
}

prepare_playcover_profile_fixture() {
  prepare_playcover_hook_mode
  prepare_playcover_profile_calendar
  PLAYCOVER_PROFILE_FIXTURE_NAME="${PLAYCOVER_PROFILE_FIXTURE:-baseline}"
  PLAYCOVER_PROFILE_BASE_POINT=0
  PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[]'
  PLAYCOVER_PROFILE_EVENT_IDS_JSON='[]'
  PLAYCOVER_PROFILE_DUNGEON_RECORDS_JSON='[]'
  PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[]'
  PLAYCOVER_PROFILE_ITEM_RECORDS_JSON='[]'
  PLAYCOVER_PROFILE_INGREDIENT_RECORDS_JSON='[]'
  case "$PLAYCOVER_PROFILE_FIXTURE_NAME" in
    baseline)
      ;;
    event-902)
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902]'
      ;;
    event-903)
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[903]'
      ;;
    event-904)
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[904]'
      ;;
    event-905)
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[905]'
      ;;
    event-914)
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[914]'
      ;;
    training-just-unlocked)
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902]'
      set_playcover_profile_calendar_claimed_today
      ;;
    kingdom-just-unlocked)
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[906]'
      ;;
    kingdom-quest-ready)
      PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[[0,72,10]]'
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[906]'
      ;;
    inventory-type10-item-ready)
      PLAYCOVER_PROFILE_ITEM_RECORDS_JSON='[{"recordId":1,"factoryParam3Bits":0,"factoryParam5Bits":0,"itemType":10,"stateByte":1,"equippedSlot":null}]'
      set_playcover_profile_calendar_claimed_today
      ;;
    inventory-type1-bow-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_ITEM_RECORDS_JSON='[{"recordId":1,"factoryParam3Bits":0,"factoryParam5Bits":1,"itemType":1,"stateByte":1,"equippedSlot":null,"commonByte":4,"type1Field10":18,"type1Field4":1}]'
      ;;
    inventory-type2-armor-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_ITEM_RECORDS_JSON='[{"recordId":1,"factoryParam3Bits":0,"factoryParam5Bits":1,"itemType":2,"stateByte":1,"equippedSlot":null,"commonByte":4,"type2Field10A":20,"type2Field10B":15}]'
      ;;
    ingredient-id0-count1-readonly)
      PLAYCOVER_PROFILE_BASE_POINT=12800
      PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[[1,8,9]]'
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902,903,904,905,906,914]'
      PLAYCOVER_PROFILE_INGREDIENT_RECORDS_JSON='[{"ingredientId":0,"quantity":1}]'
      ;;
    inventory-type19-hat-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_ITEM_RECORDS_JSON='[{"recordId":1,"factoryParam3Bits":0,"factoryParam6Bits":0,"itemType":19,"stateByte":1,"commonByte":0,"type19Field10A":0,"type19Field10B":0,"type19Field10C":0,"type19Field10D":0,"commonField4A":1,"commonField4B":5,"commonField32":0}]'
      set_playcover_profile_calendar_claimed_today
      ;;
    inventory-type20-boots-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_ITEM_RECORDS_JSON='[{"recordId":1,"factoryParam3Bits":0,"factoryParam6Bits":0,"itemType":20,"stateByte":1,"commonByte":0,"type20Field10A":0,"type20Field10B":0,"type20Field10C":0,"commonField4A":1,"commonField4B":5,"commonField32":0}]'
      set_playcover_profile_calendar_claimed_today
      ;;
    inventory-type4-ring-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_ITEM_RECORDS_JSON='[{"recordId":1,"factoryParam3Bits":0,"factoryParam5Bits":0,"itemType":4,"stateByte":1,"equippedSlot":null,"commonByte":0,"type4Field10A":0,"type4Field10B":0,"type4Field10C":0,"nestedMode":0,"nestedCount":0}]'
      ;;
    inventory-type12-spirit-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_ITEM_RECORDS_JSON='[{"recordId":1,"factoryParam3Bits":0,"factoryParam5Bits":9,"itemType":12,"stateByte":10,"equippedSlot":null,"commonByte":0,"type12Field10A":0,"type12Field10B":0,"type12Field10C":0,"nestedMode":0,"nestedCount":0}]'
      ;;
    shop-type10-item-ready)
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[914]'
      PLAYCOVER_PROFILE_ITEM_RECORDS_JSON='[{"recordId":1,"factoryParam3Bits":0,"factoryParam5Bits":0,"itemType":10,"stateByte":1,"equippedSlot":null}]'
      ;;
    ordinary-all)
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902,903,904,905,906,914]'
      ;;
    calendar-day1-available)
      ;;
    calendar-day2-with-day1-readonly)
      PLAYCOVER_PROFILE_CALENDAR_JSON="{\"curTick\":$PLAYCOVER_PROFILE_CALENDAR_CUR_TICK,\"lastDailyRewardTick\":$((PLAYCOVER_PROFILE_CALENDAR_CUR_TICK - 86400001)),\"cumulativeDailyRewardCounter\":1}"
      ;;
    calendar-claimed-today-suppressed)
      set_playcover_profile_calendar_claimed_today
      ;;
    raid-49)
      PLAYCOVER_PROFILE_BASE_POINT=12544
      ;;
    raid-50)
      PLAYCOVER_PROFILE_BASE_POINT=12800
      ;;
    raid-populated)
      PLAYCOVER_PROFILE_BASE_POINT=12800
      set_playcover_profile_calendar_claimed_today
      ;;
    dungeon-before)
      PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[[1,8,8]]'
      ;;
    dungeon-cleared)
      PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[[1,8,9]]'
      ;;
    dungeon-all-groups)
      PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[[0,8,9],[1,8,9],[0,72,10],[0,82,10],[0,92,10],[0,87,11]]'
      PLAYCOVER_PROFILE_DUNGEON_RECORDS_JSON='[{"dungeonKey":0,"booleanState":true,"stageRecords":[],"trailingByte":0},{"dungeonKey":7,"booleanState":true,"stageRecords":[],"trailingByte":0},{"dungeonKey":9,"booleanState":true,"stageRecords":[],"trailingByte":0},{"dungeonKey":11,"booleanState":true,"stageRecords":[],"trailingByte":0}]'
      ;;
    world-story-hard)
      PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[[0,8,9]]'
      set_playcover_profile_calendar_claimed_today
      ;;
    world-zone-a)
      PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[[0,8,9],[1,8,9]]'
      set_playcover_profile_calendar_claimed_today
      ;;
    world-zones-bcd)
      PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[[0,8,9],[1,8,9],[0,72,10]]'
      set_playcover_profile_calendar_claimed_today
      ;;
    world-all-cleared)
      PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[[0,8,9],[1,8,9],[0,72,10],[0,82,10],[0,92,10],[0,87,11]]'
      set_playcover_profile_calendar_claimed_today
      ;;
    story-map1-stage1-clear)
      PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[[0,1,1]]'
      PLAYCOVER_PROFILE_ITEM_RECORDS_JSON='[{"recordId":1,"factoryParam3Bits":0,"factoryParam5Bits":1,"itemType":1,"stateByte":1,"equippedSlot":0,"commonByte":4,"type1Field10":18,"type1Field4":1}]'
      set_playcover_profile_calendar_claimed_today
      ;;
    story-map1-stage4-clear)
      PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[[0,1,4]]'
      set_playcover_profile_calendar_claimed_today
      ;;
    training-missile-ready)
      PLAYCOVER_PROFILE_BASE_POINT=3840
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902]'
      PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[{"skillId":2,"level":3,"stateFlag":0}]'
      ;;
    training-barrier-ready)
      PLAYCOVER_PROFILE_BASE_POINT=5120
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902]'
      ;;
    training-powershot-state-flag)
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902]'
      PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[{"skillId":1,"level":0,"stateFlag":1}]'
      ;;
    training-powershot-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902]'
      PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[{"skillId":1,"level":0,"stateFlag":1}]'
      ;;
    training-multishot-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902]'
      PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[{"skillId":1,"level":1,"stateFlag":0},{"skillId":2,"level":0,"stateFlag":1}]'
      ;;
    training-lightningshot-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902]'
      PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[{"skillId":1,"level":1,"stateFlag":0},{"skillId":3,"level":0,"stateFlag":1}]'
      ;;
    training-iceshot-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902]'
      PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[{"skillId":1,"level":1,"stateFlag":0},{"skillId":4,"level":0,"stateFlag":1}]'
      ;;
    training-poisonshot-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902]'
      PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[{"skillId":1,"level":1,"stateFlag":0},{"skillId":5,"level":0,"stateFlag":1}]'
      ;;
    training-cannonshot-ready)
      PLAYCOVER_PROFILE_BASE_POINT=5120
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902]'
      PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[{"skillId":1,"level":3,"stateFlag":0},{"skillId":6,"level":0,"stateFlag":1}]'
      ;;
    training-thunderstormshot-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902,903]'
      PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[{"skillId":3,"level":1,"stateFlag":0},{"skillId":8,"level":0,"stateFlag":1}]'
      ;;
    training-blizzardshot-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902,903]'
      PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[{"skillId":4,"level":3,"stateFlag":0},{"skillId":9,"level":0,"stateFlag":1}]'
      ;;
    training-poisoncloudshot-ready)
      PLAYCOVER_PROFILE_BASE_POINT=256
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902,903]'
      PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[{"skillId":5,"level":3,"stateFlag":0},{"skillId":10,"level":0,"stateFlag":1}]'
      ;;
    shortcut-all-learned)
      PLAYCOVER_PROFILE_BASE_POINT=5120
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902,903,904,905,906,914]'
      PLAYCOVER_PROFILE_SKILL_RECORDS_JSON='[{"skillId":1,"level":3,"stateFlag":0},{"skillId":2,"level":3,"stateFlag":0},{"skillId":3,"level":1,"stateFlag":0},{"skillId":4,"level":3,"stateFlag":0},{"skillId":5,"level":3,"stateFlag":0},{"skillId":6,"level":1,"stateFlag":0},{"skillId":7,"level":1,"stateFlag":0},{"skillId":8,"level":1,"stateFlag":0},{"skillId":9,"level":1,"stateFlag":0},{"skillId":10,"level":1,"stateFlag":0},{"skillId":11,"level":1,"stateFlag":0},{"skillId":13,"level":1,"stateFlag":0}]'
      ;;
    all-local)
      PLAYCOVER_PROFILE_BASE_POINT=12800
      PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON='[[1,8,9]]'
      PLAYCOVER_PROFILE_EVENT_IDS_JSON='[902,903,904,905,906,914]'
      ;;
    *)
      echo "Unsupported PLAYCOVER_PROFILE_FIXTURE: $PLAYCOVER_PROFILE_FIXTURE_NAME" >&2
      echo "Expected one of: baseline, event-902, event-903, event-904, event-905, event-914, training-just-unlocked, kingdom-just-unlocked, kingdom-quest-ready, inventory-type10-item-ready, inventory-type1-bow-ready, inventory-type2-armor-ready, ingredient-id0-count1-readonly, inventory-type19-hat-ready, inventory-type20-boots-ready, inventory-type4-ring-ready, inventory-type12-spirit-ready, shop-type10-item-ready, ordinary-all, calendar-day1-available, calendar-day2-with-day1-readonly, calendar-claimed-today-suppressed, raid-49, raid-50, raid-populated, dungeon-before, dungeon-cleared, dungeon-all-groups, world-story-hard, world-zone-a, world-zones-bcd, world-all-cleared, story-map1-stage1-clear, story-map1-stage4-clear, training-missile-ready, training-barrier-ready, training-powershot-state-flag, training-powershot-ready, training-multishot-ready, training-lightningshot-ready, training-iceshot-ready, training-poisonshot-ready, training-cannonshot-ready, training-thunderstormshot-ready, training-blizzardshot-ready, training-poisoncloudshot-ready, shortcut-all-learned, all-local" >&2
      exit 1
      ;;
  esac
}

open_playcover_app() {
  local app="$1"
  prepare_playcover_batch_token
  open -n \
    --env "ARCHERCAT_BATCH_TOKEN=$PLAYCOVER_BATCH_TOKEN" \
    --env "ARCHERCAT_PROFILE_FIXTURE=$PLAYCOVER_PROFILE_FIXTURE_NAME" \
    --env "ARCHERCAT_PROFILE_BASE_POINT=$PLAYCOVER_PROFILE_BASE_POINT" \
    --env "ARCHERCAT_PROFILE_MAP_CLEAR_TUPLES=$PLAYCOVER_PROFILE_MAP_CLEAR_TUPLES_JSON" \
    --env "ARCHERCAT_PROFILE_EVENT_IDS=$PLAYCOVER_PROFILE_EVENT_IDS_JSON" \
    --env "ARCHERCAT_PROFILE_DUNGEON_RECORDS=$PLAYCOVER_PROFILE_DUNGEON_RECORDS_JSON" \
    --env "ARCHERCAT_PROFILE_SKILL_RECORDS=$PLAYCOVER_PROFILE_SKILL_RECORDS_JSON" \
    --env "ARCHERCAT_PROFILE_ITEM_RECORDS=$PLAYCOVER_PROFILE_ITEM_RECORDS_JSON" \
    --env "ARCHERCAT_PROFILE_INGREDIENT_RECORDS=$PLAYCOVER_PROFILE_INGREDIENT_RECORDS_JSON" \
    --env "ARCHERCAT_PROFILE_CALENDAR=$PLAYCOVER_PROFILE_CALENDAR_JSON" \
    --env "ARCHERCAT_HOOK_MODE=$PLAYCOVER_HOOK_MODE_NAME" \
    "$app"
}

require_uv_runtime() {
  local root_dir="$1"

  if ! command -v uv >/dev/null 2>&1; then
    echo "uv is required for PlayCover runtime dependencies. Install uv, then run: bun run runtime:setup" >&2
    exit 1
  fi

  if ! uv sync --project "$root_dir" --locked --check >/dev/null 2>&1; then
    echo "Python runtime dependencies are not synchronized. Run: bun run runtime:setup" >&2
    exit 1
  fi
}

set_frida_cmd() {
  local root_dir="$1"

  if [[ -n "${FRIDA:-}" ]]; then
    if [[ ! -x "$FRIDA" ]]; then
      echo "FRIDA is set but is not executable: $FRIDA" >&2
      exit 1
    fi
    FRIDA_CMD=("$FRIDA")
    return
  fi

  require_uv_runtime "$root_dir"
  FRIDA_CMD=(uv run --project "$root_dir" --locked --no-sync frida)
}
