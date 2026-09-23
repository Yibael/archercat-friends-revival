#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
export LC_ALL=C
export PYTHONDONTWRITEBYTECODE=1
cd "$ROOT"
finish() {
  local status=$?
  if [[ -t 0 && "${ARCHERCAT_NONINTERACTIVE:-0}" != 1 ]]; then
    printf '\n启动器已结束（code=%s）。按回车关闭。\n' "$status"
    read -r _ || true
  fi
}
trap finish EXIT
if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo '此体验包仅支持 Apple Silicon Mac；请使用原生 arm64 Terminal。' >&2; exit 1
fi
if ! command -v uv >/dev/null; then
  echo '请先安装 uv：https://docs.astral.sh/uv/getting-started/installation/' >&2; exit 1
fi
if ! xcrun --find dwarfdump >/dev/null 2>&1; then
  echo '请先运行 xcode-select --install 安装 Apple Command Line Tools。无需完整 Xcode。' >&2; exit 1
fi
export ARCHERCAT_APP_PATH="${ARCHERCAT_APP_PATH:-$HOME/Library/Containers/io.playcover.PlayCover/Applications/net.cravemob.archercatfriends.app}"
# Original guards run before dependency downloads, mock startup, or game launch.
source "$ROOT/runtime-revive/playcover-spike/playcover-runtime-env.sh"
refuse_existing_archercat_targets
if /usr/bin/nc -z 127.0.0.1 3001 >/dev/null 2>&1; then
  echo '本机 3001 端口已被使用；不会接管或终止已有服务。' >&2; exit 1
fi
if [[ -e "${TMPDIR:-/tmp}/archercat-playcover-capture-mock.lock" ]]; then
  echo '已有 ArcherCat batch lock；保留现场并停止。' >&2; exit 1
fi
echo '正在准备 Python / Frida（Frida 从仓库安装；缺少 Python 3.12 时会自动下载）…'
uv sync --project "$ROOT" --locked --python 3.12
PREPARE_ARGS=()
if [[ "${ARCHERCAT_NONINTERACTIVE:-0}" == 1 ]]; then
  PREPARE_ARGS+=(--non-interactive)
fi
uv run --project "$ROOT" --locked --no-sync python "$ROOT/tools/prepare_game.py" "${PREPARE_ARGS[@]}"
export PLAYCOVER_HOOK_MODE=light
export PLAYCOVER_PROFILE_FIXTURE=calendar-claimed-today-suppressed
export PLAYCOVER_REQUIRE_OWN_MOCK=1
export PLAYCOVER_REQUIRE_TARGET_STOPPED_ON_EXIT=1
export PLAYCOVER_LAUNCH_SCRIPT="$ROOT/runtime-revive/playcover-spike/launch-player.sh"
echo '这是本地体验包，暂不保证进度保存和完整游戏流程。'
echo '游戏运行时请保留此终端；退出游戏会自动停止 mock。Ctrl+C 可结束本次运行。'
"$ROOT/runtime-revive/playcover-spike/start-with-local-mock.sh"
