# 运行验证记录

## 2026-09-23：最终干净克隆验收

从 Git 创建新的完整克隆，目录名包含空格；初始没有 `.venv` 或运行日志，uv 使用新的空缓存。设置 `UV_OFFLINE=1`，由仓库内的官方 wheel 安装 Frida，安装仅耗时约 0.2 秒，不访问 PyPI。

同一次 `Start.command` 随后成功启动 mock 和原游戏、验证 light hooks 与 LocalGuest 登录，并在 ready 后持续运行 30.11 秒。退出码为 0；随后以精确身份关闭本批次游戏，mock 和 batch lock 正常释放。收尾审计确认没有游戏进程或 TCP 3001 listener 残留。

这里验证的是“干净代码克隆 + 已安装的系统工具和 PlayCover 游戏”的启动流程。Python 3.12 使用本机已有解释器；缺少 Python 时的自动下载、全新 Mac 上的 PlayCover IPA 首次导入仍未经过实机验证。首次导入分支由离线测试覆盖。没有发送游戏输入，也没有据此认定战斗、结算、持久存档或长时间运行可靠。

可在完成首次安装后复现限时启动检查：

```sh
ARCHERCAT_NONINTERACTIVE=1 ARCHERCAT_SMOKE_SECONDS=30 UV_OFFLINE=1 ./Start.command
```

## 2026-09-23：早期运行记录

早期结论：**一键启动和本地登录链路已验证，当次稳定运行未通过。**

本次测试使用已有的 PlayCover 安装，未在全新用户、全新安装或另一台 Mac 上验证。

- 系统：macOS 27.0 / arm64，PlayCover 3.1.0。
- 依赖：独立安装 Python 3.12、frida 17.15.4、frida-tools 14.10.4。
- mock：成功监听 `127.0.0.1:3001`。
- 游戏：改用实际 PlayCover 容器应用后启动成功；外层快捷入口曾返回 `-54 / permErr`。
- hook：`light` 模式的 5 个预期 hooks 全部就绪。
- 登录：`requestType=3` 的 LocalGuest 响应被替换并验证，实际与预期长度均为 9988 字节。
- 稳定性：计划保持 30 秒，实际在 hook 就绪后约 11 秒提前退出。系统崩溃报告为 `EXC_BAD_ACCESS / SIGSEGV / KERN_INVALID_ADDRESS at 0x0`。
- 收尾：目标游戏、本次 mock、TCP 3001 listener 和 batch lock 均已退出或释放。

同时观察到尚未专门实现的 EatFish / UpdateFish 等请求；尚未证明它们与崩溃的因果关系。没有自动发送游戏输入，没有以截图或场景采集确认主页或战斗。因此这里的成功证据止于进程、hook 和本地登录响应。

限时 smoke 曾把提前退出当成普通结束，后来已改为返回失败并加入测试。日志降噪和新退出判断经过离线验证，修改后经过上方的最终干净克隆测试，提前退出仍按失败处理。

本次发布还删除了 IPA 中未使用的旧 `archived-expanded-entitlements.xcent`。与原 IPA 逐成员比较，其余文件内容全部相同；删除元数据后的首次 PlayCover 导入尚未重新实测。

## 离线测试覆盖

`test_player.py` 覆盖：

1. 拒绝错误 PID、不完整 hook 集合和错误 fixture。
2. 校验登录 fixture、响应长度及 LocalGuest 标记。
3. 拒绝对已复用的 PID 执行清理。
4. 拒绝不属于本批次 token 的目标。
5. 仅对已校验身份发送一次 SIGTERM。
6. 检查 GetServerStatus 和 LoginUser 的 mock wire 形状。
7. 将限时 smoke 的提前退出判为失败。

`tools/check_distribution.py` 检查公开文件清单、hash、隐私/凭据模式及 IPA 成员。检查不启动游戏，也不代替运行验证。

## 后续验收

定位现有崩溃，补齐实际响应与存档语义后，再验证：首次安装 → 启动 → 单关战斗 → 结算 → 保存 → 退出 → 再次启动。最后在另一台干净 Mac 上重做安装及游玩验证。

## 仓库独立性验证

首次导入准备分支增加了 6 项行为测试，分发检查增加了 4 项隐私/归档测试；共 17 项离线测试。验证时不使用原始逆向仓库的运行目录、虚拟环境或测试日志。干净克隆会从锁文件建立新环境；实际 PlayCover 安装仍属于系统级前置环境，不能据此宣称已在另一台全新 Mac 上通过。

首次空缓存在线安装遇到 PyPI 超时，发生在任何 mock/game launch 之前。最终依赖改为只保留 Frida Python API，并随仓库提供经过原锁文件 SHA-256 校验的官方 macOS ARM64 wheel。`frida-tools` 及其间接依赖不再属于运行环境；uv 从仓库内文件安装 Frida。
