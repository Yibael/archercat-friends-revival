"""First-run import of the bundled IPA through the user's installed PlayCover."""
import argparse
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
APP_RELATIVE = 'Library/Containers/io.playcover.PlayCover/Applications/net.cravemob.archercatfriends.app'


def installed_app():
    expected = Path.home() / APP_RELATIVE
    override = os.environ.get('ARCHERCAT_APP_PATH')
    if override and Path(override).expanduser().resolve() != expected.resolve():
        raise RuntimeError('This launcher requires the standard PlayCover installation directory.')
    return expected


def verify_app(app):
    binary = app / 'ArcherCatXFacebook'
    if not (app / 'Info.plist').is_file() or not binary.is_file():
        return False
    result = subprocess.run(['codesign', '--verify', '--deep', '--strict', str(app)],
                            capture_output=True, text=True, timeout=20)
    return result.returncode == 0


def find_playcover():
    override = os.environ.get('PLAYCOVER_APP_PATH')
    paths = [Path(override).expanduser()] if override else [
        Path('/Applications/PlayCover.app'), Path.home() / 'Applications/PlayCover.app']
    for path in paths:
        if (path / 'Contents/Info.plist').is_file():
            return path
    raise RuntimeError('请先安装 PlayCover 到 Applications；自定义位置可设置 PLAYCOVER_APP_PATH。')


def verify_ipa(root):
    ipa = root / 'runtime-revive/ArcherCat-unsigned-resignable.ipa'
    provenance = json.loads((root / 'PROVENANCE.json').read_text())
    if not ipa.is_file() or hashlib.sha256(ipa.read_bytes()).hexdigest() != provenance['distributedIpaSha256']:
        raise RuntimeError('仓库内 IPA 缺失或校验失败，请重新下载完整项目。')
    return ipa


def prepare(root=ROOT, noninteractive=False, timeout=300):
    app = installed_app()
    if app.exists():
        if not verify_app(app):
            raise RuntimeError('已有 PlayCover 游戏安装未通过完整性检查；未覆盖安装，请检查后重试。')
        return app
    if noninteractive:
        raise RuntimeError('首次导入需要 PlayCover 窗口；请先正常运行 Start.command 完成导入。')
    ipa = verify_ipa(root)
    playcover = find_playcover()
    print('首次运行：正在让 PlayCover 导入仓库内 IPA。请完成 PlayCover 显示的安装提示。', flush=True)
    print('安装完成后此终端会继续启动游戏；无需手动寻找 IPA，也不要另外打开游戏。', flush=True)
    # Exactly one import request, and never overwrite an existing installation.
    if app.exists():
        raise RuntimeError('导入前检测到新的安装目录，已停止，未覆盖。')
    subprocess.run(['open', '-a', str(playcover), str(ipa)], check=True, timeout=20)
    deadline = time.monotonic() + timeout
    next_notice = time.monotonic() + 20
    while time.monotonic() < deadline:
        if app.exists() and verify_app(app):
            print('PlayCover 安装已完成，继续启动。', flush=True)
            return app
        if time.monotonic() >= next_notice:
            print('等待 PlayCover 完成导入…（Ctrl+C 可取消）', flush=True)
            next_notice = time.monotonic() + 20
        time.sleep(1)
    raise RuntimeError('等待导入超时；没有启动 mock 或游戏。请完成 PlayCover 安装后重新运行。')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--non-interactive', action='store_true')
    args = parser.parse_args()
    try:
        prepare(noninteractive=args.non_interactive)
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'准备游戏失败：{error}', file=sys.stderr)
        raise SystemExit(1)
