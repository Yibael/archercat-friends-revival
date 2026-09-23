# ArcherCat Friends Revival

使用 **PlayCover + Frida + 本地 mock**，在 Apple Silicon Mac 上运行 ArcherCat Friends 原版客户端的非官方实验项目。

安装好必要工具后，克隆仓库并双击 **`Start.command`**，即可一起启动游戏、本地 mock 和 Frida。无需克隆原始逆向仓库，也不需要 Bun、Node.js 或 Codex。

> **当前不是稳定可玩的游戏发行版。** 已实测启动、网络重定向和本地登录；最近一次运行在 hook 就绪约 11 秒后出现 `EXC_BAD_ACCESS`。完整战斗、结算和持久存档尚未验证。请将它作为复现和开发环境使用。

## 运行方式

```text
Start.command
  ├─ uv 准备独立 Python / Frida 环境
  ├─ 本地 mock：127.0.0.1:3001
  └─ PlayCover 原游戏进程
       └─ Frida：网络重定向、关联请求、替换有限的 mock 响应
```

原客户端仍负责游戏逻辑与画面。本项目的 mock 仅实现有限响应，角色数据来自固定的本地 fixture；不代表恢复了原服务端或真实玩家账号。

## 环境要求

| 项目 | 说明 |
| --- | --- |
| Apple Silicon Mac | M1 或后续芯片；本启动器不支持 Intel Mac、Windows 或 Linux |
| PlayCover | 先安装与自己 macOS 兼容的版本，首次启动时由启动器打开包内 IPA 导入 |
| Apple Command Line Tools | 用于核对游戏二进制身份；不需要完整 Xcode |
| uv | 管理独立 Python 环境和锁定的依赖 |
| 首次联网 | 下载 Python 3.12 和 Frida；后续运行不自动升级锁定依赖 |

本机验证环境为 macOS 27.0、PlayCover 3.1.0、Python 3.12、Frida 17.15.4。其他系统组合和全新 Mac 的安装流程尚未在另一台实机验证；首次导入分支有离线行为测试。Frida 注入也受本机权限影响；启动器不会修改系统安全设置。

## 首次安装

### 1. 安装基础工具

安装 [PlayCover](https://docs.playcover.io/getting_started/download_playcover)。

安装 Apple Command Line Tools：

```sh
xcode-select --install
```

按 [uv 官方说明](https://docs.astral.sh/uv/getting-started/installation/)安装 uv。已有 Homebrew 时也可使用 `brew install uv`。

### 2. 获取项目

```sh
git clone https://github.com/Yibael/archercat-friends-revival.git
cd archercat-friends-revival
```

也可以从 GitHub 下载 ZIP，完整解压到可写目录。IPA 直接保存在仓库中，不需要 Git LFS。

### 3. 首次运行与自动导入

仓库已经包含 `runtime-revive/ArcherCat-unsigned-resignable.ipa`，不需要从别的仓库或临时目录复制文件。首次执行 `Start.command` 时，如果游戏尚未安装，启动器会自动让 PlayCover 打开此 IPA，等待导入完成后继续。请完成 PlayCover 自身显示的安装提示；不要另外打开游戏。

IPA 已移除无用的旧签名 entitlement 元数据；未改动游戏二进制或资源内容。如果已有安装，启动器只检查它，不会覆盖或重装。

如需调整显示，在 PlayCover 中为游戏选择 iPhone 竖屏。

### 4. 一键启动

双击 **`Start.command`**，或在终端执行：

```sh
./Start.command
```

首次会建立 `.venv` 并下载锁定依赖，随后自动启动 mock、游戏和 Frida。若游戏出现“开始游戏”，由使用者点击。

游戏运行期间保留终端窗口。关闭游戏后启动器会收尾本次 mock，也可以按 **Ctrl+C** 结束本次运行。请勿直接从 PlayCover 单独启动游戏，否则不会同时启动本地 mock 链路。

## 当前状态

| 功能 | 状态 |
| --- | --- |
| 独立目录安装依赖 | 已验证 |
| 本地 mock 启动 | 已验证 |
| PlayCover 原游戏启动 | 已验证 |
| Frida hook 与 LocalGuest 登录响应 | 已验证 |
| 连续稳定运行 | **未通过：已观察到崩溃** |
| 单关开始 → 战斗 → 结算 | 未验证 |
| 保存进度 → 退出 → 重新启动 | 未验证 |
| 商店交易、成长、社交 | 未完整实现或验证 |
| 另一台干净 Mac / 纯离线运行 | 未验证 |

启动时使用 `calendar-claimed-today-suppressed` fixture，减少签到弹窗干扰。每次登录可能重新注入预设数据，不能把它当作可靠的个人存档系统。

详见 [测试记录](docs/testing.md)。下一步应定位现有崩溃，再验证完整的单关和存档流程。

## 常见问题

**游戏卡在连接服务器**

确认是通过 `Start.command` 启动，并保持 mock 与 Frida 存活。单独打开 PlayCover 游戏不会自动挂载本项目的 hook。

**出现 `-54` / `permErr`**

历史测试发现外层 PlayCover 快捷入口存在符号链接/签名问题。因此启动器直接使用当前用户的实际安装路径：

```text
~/Library/Containers/io.playcover.PlayCover/Applications/net.cravemob.archercatfriends.app
```

不会删除或修复已有快捷入口。如果此实际应用无法启动，请保留错误信息检查 PlayCover 安装。

**提示已有游戏、3001 端口占用或 batch lock**

启动器不会接管既有游戏、终止未知服务或盲删锁。请先确认前一次运行已退出；不要用按名称批量杀进程的方式清理。

**日志在哪里？**

在 `runtime-revive/playcover-spike/logs/` 和 `runtime-revive/playcover-spike/mock-server/logs/`。日志可能包含请求或客户端标识，已被 Git 忽略。报告问题时只提供必要且已脱敏的错误片段。

## 开发与验证

不启动游戏的检查：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v
python3 tools/check_distribution.py
bash -n Start.command
bash -n runtime-revive/playcover-spike/launch-player.sh
```

发布前更新文件清单并再次检查：

```sh
python3 tools/check_distribution.py --refresh
python3 tools/check_distribution.py
```

`--refresh` 只更新经过检查的公开文件 hash，不会自动纳入额外文件。需要加入新文件时应先审查并更新 `PUBLIC_FILES.txt`。

项目包含本地进程身份和所有权校验：仅操作本次创建并验证过的目标，游戏退出后再停止 mock。不要为了绕过错误而关闭这些校验。

## 文件与来源

- `Start.command`：双击入口。
- `player.py`：Frida 会话、登录验证和进程收尾。
- `runtime-revive/`：经过审查的 IPA、mock 和运行辅助代码。
- `PUBLIC_FILES.txt` / `DISTRIBUTION.json`：公开文件清单及 hash。
- `PROVENANCE.json`：上游版本与 IPA 处理记录。
- [隐私与分发说明](docs/privacy.md)：排除项、检查范围和限制。

ArcherCat Friends 的名称、客户端和美术资源属于原权利人。本项目不是原开发商的官方产品，也不表示取得了原游戏内容的授权许可。
