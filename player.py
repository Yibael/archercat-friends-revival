"""Experimental player host. Reuses the source project's exact process guards."""
import argparse
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'runtime-revive/playcover-spike/cocos-ui-capture'))
from capture_framebuffer_sidecar import (
    SidecarError, read_process_identity, process_identity_mismatches,
    verify_process_batch_token, require_archercat_process_ready,
)

UUID = 'CD56D3DF-A1D8-35E6-8A8C-71D948E25808'
HOOKS = ['getaddrinfo', 'connect', 'post_response_process', 'request_encrypt', 'response_decrypt']
FIXTURE = 'calendar-claimed-today-suppressed'


def validate_ready(data, pid):
    if (data.get('status') != 'ok' or data.get('pid') != pid or
        data.get('arch') != 'arm64' or data.get('hookMode') != 'light' or
        data.get('persistentHooks') != HOOKS or data.get('profileFixture') != FIXTURE or
        not isinstance(data.get('expectedLoginProfileLength'), int) or
        data['expectedLoginProfileLength'] <= 0 or
        data.get('criticalHooks') != dict.fromkeys(
            ['getaddrinfo', 'connect', 'postResponseProcess', 'responseDecrypt'], True)):
        raise RuntimeError('Network hook ready contract mismatch')


def validate_login(data, ready):
    fields = ['profileFixture', 'profileBasePoint', 'profileMapClearTuples',
              'profileEventIds', 'profileDungeonRecords', 'profileSkillRecords',
              'profileItemRecords', 'profileIngredientRecords', 'profileCalendar']
    if ready is None or any(data.get(key) != ready.get(key) for key in fields):
        raise RuntimeError('Login fixture differs from the ready fixture')
    expected = ready['expectedLoginProfileLength']
    if data.get('outputLength') != expected or data.get('expectedOutputLength') != expected:
        raise RuntimeError('Login profile length mismatch')
    if data.get('containsLocalGuest') is not True:
        raise RuntimeError('Login did not contain LocalGuest')


def validate_smoke_exit(seconds, deadline, now, detached):
    if seconds and detached and now < deadline:
        raise RuntimeError('Game exited before the smoke-test deadline; startup stability failed')


def assert_owned(identity, token):
    verify_process_batch_token(identity.pid, token)
    current = read_process_identity(identity.pid)
    mismatch = process_identity_mismatches(identity, current)
    if mismatch:
        raise RuntimeError(f'Process identity changed: {mismatch}')


def stop_owned(identity, token, emit):
    try:
        assert_owned(identity, token)
    except SidecarError as error:
        if error.status == 'target_exited':
            return
        raise
    # No by-name kill, no SIGKILL, no retry. Identity is rechecked immediately.
    os.kill(identity.pid, signal.SIGTERM)
    until = time.monotonic() + 5
    while time.monotonic() < until:
        try:
            current = read_process_identity(identity.pid)
            if process_identity_mismatches(identity, current):
                raise RuntimeError('Target identity changed during shutdown')
        except SidecarError as error:
            if error.status == 'target_exited':
                emit('target_stopped', pid=identity.pid)
                return
            raise
        time.sleep(.1)
    raise RuntimeError('Target did not exit; close the owned game window manually')


def run(args):
    import frida
    token = os.environ['PLAYCOVER_BATCH_TOKEN']
    lock = threading.Lock()
    stream = Path(args.log).open('a', encoding='utf-8')
    def emit(kind, **fields):
        with lock:
            stream.write(json.dumps({'time': time.time(), 'kind': kind, **fields}, ensure_ascii=False)+'\n')
            stream.flush()
    stop = threading.Event()
    detached = threading.Event()
    ready_event = threading.Event()
    ready = None
    errors = []
    login_seen = False
    session = None
    script = None
    identity = None
    result = 0
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: stop.set())
    def on_message(message, _data):
        nonlocal ready, login_seen
        emit('frida_message', message=message)
        try:
            if message.get('type') == 'error':
                raise RuntimeError(message.get('description', 'Frida script error'))
            data = message.get('payload', {})
            if not isinstance(data, dict):
                return
            kind = data.get('kind')
            if kind == 'network_redirect_hook_bootstrap_error':
                raise RuntimeError(data.get('error', 'Hook bootstrap failed'))
            if kind == 'network_redirect_hook_ready':
                validate_ready(data, args.pid)
                ready = data
                ready_event.set()
            if kind == 'network_redirect_audit' and data.get('eventKind') == 'archercat_response_decrypt_mocked' and data.get('requestType') in (3, 4):
                validate_login(data, ready)
                login_seen = True
                print('已核对本地登录响应；游戏界面仍需实际观察。', flush=True)
        except Exception as error:
            errors.append(str(error))
            ready_event.set()
            stop.set()
    try:
        verify_process_batch_token(args.pid, token)
        identity = read_process_identity(args.pid)
        expected_path = (Path.home() / 'Library/Containers/io.playcover.PlayCover/Applications/net.cravemob.archercatfriends.app/ArcherCatXFacebook').resolve()
        if identity.executable != expected_path or not any(x == {'uuid': UUID, 'arch': 'arm64'} for x in identity.identities):
            raise RuntimeError('Installed binary path/UUID is not the supported ArcherCat build')
        emit('target_identity', identity=identity.as_dict())
        assert_owned(identity, token)
        require_archercat_process_ready(args.pid)
        session = frida.get_local_device().attach(args.pid)
        session.on('detached', lambda *reason: (emit('detached', reason=reason), detached.set(), ready_event.set()))
        script = session.create_script((ROOT / 'runtime-revive/playcover-spike/frida-network-redirect-hook.js').read_text())
        script.on('message', on_message)
        # Suppress raw telemetry that may contain cached client tokens.
        script.set_log_handler(lambda _level, _text: None)
        script.load()
        if not ready_event.wait(12) or ready is None or errors or detached.is_set():
            raise RuntimeError('Hook failed to become ready: ' + '; '.join(errors))
        assert_owned(identity, token)
        emit('ready_verified', pid=args.pid, hookMode=ready['hookMode'], profileFixture=ready['profileFixture'])
        print('启动完成：原游戏 + 本地 mock + Frida 已连接。', flush=True)
        print('请在游戏窗口操作；此版本不保证进度保存。关闭游戏或按 Ctrl+C 结束。', flush=True)
        deadline = time.monotonic()+args.seconds if args.seconds else None
        while not stop.wait(.2) and not detached.is_set():
            if deadline and time.monotonic() >= deadline:
                break
        if errors:
            raise RuntimeError('; '.join(errors))
        validate_smoke_exit(args.seconds, deadline, time.monotonic(), detached.is_set())
        emit('session_end', loginResponseObserved=login_seen, timedSmoke=bool(args.seconds))
    except Exception as error:
        result = 1
        emit('failure', error=str(error))
        print(f'启动/运行失败：{error}', file=sys.stderr, flush=True)
    finally:
        if identity is not None:
            try:
                stop_owned(identity, token, emit)
            except Exception as error:
                result = 1
                emit('cleanup_blocked', error=str(error))
                print(f'无法安全关闭目标：{error}。保留 hook 和 mock；请关闭游戏窗口。', file=sys.stderr, flush=True)
                # Preserve network protection until exact original target exits.
                # No new signals or automatic retries of the failed operation.
                while True:
                    try:
                        current = read_process_identity(identity.pid)
                        if process_identity_mismatches(identity, current):
                            emit('uncontrolled_target', pid=identity.pid)
                            break
                    except SidecarError as error:
                        if error.status == 'target_exited':
                            break
                        time.sleep(1)
                        continue
                    time.sleep(.5)
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        stream.close()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--log', required=True)
    parser.add_argument('--seconds', type=int, default=0)
    args = parser.parse_args()
    if args.pid <= 0 or args.seconds < 0:
        parser.error('pid must be positive; seconds must be nonnegative')
    raise SystemExit(run(args))
