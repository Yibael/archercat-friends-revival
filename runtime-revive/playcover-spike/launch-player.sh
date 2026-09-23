#!/bin/bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/runtime-revive/playcover-spike/playcover-runtime-env.sh"
set_uv_run_cmd "$ROOT_DIR"
require_uv_runtime "$ROOT_DIR"
prepare_playcover_profile_fixture
require_existing_playcover_batch_token
refuse_existing_archercat_targets
APP="${ARCHERCAT_APP_PATH:-$HOME/Library/Containers/io.playcover.PlayCover/Applications/net.cravemob.archercatfriends.app}"
[[ -d "$APP" ]] || { echo "PlayCover app not found: $APP" >&2; exit 1; }
LOG_DIR="$ROOT_DIR/runtime-revive/playcover-spike/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/player-$(date '+%Y%m%d-%H%M%S')-$PLAYCOVER_BATCH_TOKEN.jsonl"
reserve_new_output_file "$LOG_FILE" 'player log'
# One LaunchServices request. No automatic launch/attach retry.
open_playcover_app "$APP"
PID="$(wait_for_playcover_batch_target 100)"
verify_playcover_batch_target "$PID"
[[ -n "${PLAYCOVER_CAPTURE_TARGET_PID_FILE:-}" ]] || { echo 'Missing owned target record path.' >&2; exit 1; }
(set -o noclobber; printf '%s\n' "$PID" > "$PLAYCOVER_CAPTURE_TARGET_PID_FILE")
echo "日志: $LOG_FILE"
exec "${UV_RUN[@]}" python "$ROOT_DIR/player.py" --pid "$PID" --log "$LOG_FILE" --seconds "${ARCHERCAT_SMOKE_SECONDS:-0}"
