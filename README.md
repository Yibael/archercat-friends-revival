<div align="center">
  <img src="docs/assets/archercat-icon.png" alt="ArcherCat Friends icon" width="112" height="112">

  <h1>ArcherCat Friends Revival</h1>

  <p>在 Apple Silicon Mac 上重新启动 ArcherCat Friends。</p>
  <p>PlayCover · Frida · Local mock</p>

  <p>
    <img src="https://img.shields.io/badge/macOS-Apple%20Silicon-111827?logo=apple&amp;logoColor=white" alt="Platform: macOS on Apple Silicon">
    <img src="https://img.shields.io/badge/Python-3.12-3776AB?logo=python&amp;logoColor=white" alt="Python 3.12">
    <img src="https://img.shields.io/badge/status-experimental-orange" alt="Status: experimental">
  </p>

  <p>
    <a href="#快速开始">快速开始</a> ·
    <a href="#项目状态">项目状态</a> ·
    <a href="docs/testing.md">测试记录</a> ·
    <a href="#参与开发">参与开发</a>
  </p>
</div>

---

ArcherCat Friends Revival 是一个非官方的原版客户端运行实验。项目通过 PlayCover 运行游戏，使用 Frida 和本地 mock 补充有限的服务响应，提供可复现的一键启动环境。

- **一键启动**：同一个入口准备依赖、启动 mock、运行游戏并挂载 Frida。
- **仓库自包含**：IPA 和固定版本的 macOS ARM64 Frida wheel 随仓库提供，无需 Git LFS，也无需访问 PyPI 安装 Frida。
- **可核对的验证结果**：干净克隆已通过本地登录和 30 秒启动测试；文件来源、校验值与测试边界均有记录。

> [!IMPORTANT]
> 项目仍处于实验阶段。启动成功不代表完整游戏已经恢复：长期稳定性、战斗结算和持久存档尚未验证，此前也观察到过崩溃。当前角色数据来自预设配置，请勿将其视为可靠的个人存档系统。

## 环境要求

| 环境 | 要求 |
| --- | --- |
| 硬件 | Apple Silicon Mac，M1 或后续芯片 |
| PlayCover | 手动安装与自己 macOS 兼容的版本 |
| Apple Command Line Tools | 手动安装，用于核对游戏二进制身份 |
| uv | 手动安装，用于管理 Python 和锁定依赖 |
| Python 3.12 | 已安装时直接使用；缺少时由 uv 下载，也可提前手动安装 |

本启动器不支持 Intel Mac、Windows 或 Linux。已测试的系统组合及其限制见[测试记录](docs/testing.md)。

## 快速开始

### 1. 安装基础工具

按照官方说明安装 [PlayCover](https://docs.playcover.io/getting_started/download_playcover) 和 [uv](https://docs.astral.sh/uv/getting-started/installation/)。

安装 Apple Command Line Tools：

```sh
xcode-select --install
```

### 2. 克隆并启动

```sh
git clone https://github.com/Yibael/archercat-friends-revival.git
cd archercat-friends-revival
./Start.command
```

也可以下载仓库 ZIP，完整解压到可写目录后，双击 **`Start.command`**。

首次启动时，启动器会：

1. 创建 `.venv`，从仓库内的官方 wheel 安装 Frida。
2. 检查游戏安装；如尚未安装，打开 PlayCover 导入仓库内的 IPA。
3. 等待导入完成，再启动本地 mock、游戏和 Frida。

请完成 PlayCover 显示的安装提示。如果游戏出现“开始游戏”，点击即可。若需调整显示，可在 PlayCover 中选择 iPhone 竖屏。已有的游戏安装不会被自动覆盖。

Frida 安装不需要访问 PyPI；本机缺少 Python 3.12 时，uv 仍需要联网下载 Python。macOS 的安装或调试权限提示需要由使用者处理，启动器不会修改系统安全设置。

### 3. 退出

游戏运行期间保留启动器终端。关闭游戏后会收尾本次 mock，也可以在终端按 **Ctrl+C** 结束本次运行。

后续仍通过 `Start.command` 启动；单独从 PlayCover 打开游戏不会同时启动本地 mock 和 Frida。

## 项目状态

| 范围 | 状态 |
| --- | --- |
| 干净克隆、空 uv 缓存、离线安装 Frida | 已验证 |
| 原游戏启动、本地 mock、LocalGuest 登录 | 已验证 |
| 30 秒启动测试及受控退出 | 已通过 |
| 全新 Mac 的首次 IPA 导入 | 未经实机验证；导入分支有离线测试 |
| 长时间运行 | 未验证；历史崩溃原因尚未确认 |
| 完整战斗、结算、成长与持久存档 | 未完整实现或验证 |
| 游戏全程离线运行 | 未验证 |

这里的“离线安装”仅指依赖安装过程，不代表原游戏所有功能都能离线使用。完整验证方法和历史结果见[测试记录](docs/testing.md)。

下一步重点是定位历史崩溃，补齐实际服务响应，并验证“进入关卡 → 战斗 → 结算 → 保存 → 退出 → 再次启动”的完整流程。

## 工作原理

```text
Start.command
  ├── uv → Python + Frida
  ├── Local mock → 127.0.0.1:3001
  └── PlayCover → ArcherCat Friends
                    └── Frida 重定向请求并替换已支持的响应
```

画面和游戏逻辑仍由原客户端执行。本地 mock 只覆盖部分接口，不是原服务端的完整实现。启动器会核对进程身份及批次归属，不会接管已有游戏或终止未知服务。

## 常见问题

<details>
<summary>游戏卡在连接服务器</summary>

请确认使用 `Start.command` 启动，并保持 mock 与 Frida 存活。直接打开 PlayCover 中的游戏不会自动加载本项目的运行环境。

</details>

<details>
<summary>出现 <code>-54</code> / <code>permErr</code></summary>

历史测试发现 PlayCover 的外层快捷入口存在符号链接或签名问题。启动器已改用当前用户的实际安装路径：

```text
~/Library/Containers/io.playcover.PlayCover/Applications/net.cravemob.archercatfriends.app
```

如果此应用仍无法启动，请保留错误信息并检查 PlayCover 安装。启动器不会自动删除或修复已有快捷入口。

</details>

<details>
<summary>提示已有游戏、3001 端口占用或 batch lock</summary>

请先确认前一次运行已经退出。启动器不会接管未知进程或盲删锁；不要直接按进程名称批量清理。

</details>

<details>
<summary>在哪里查看日志？</summary>

日志生成在以下目录，均已被 Git 忽略：

- `runtime-revive/playcover-spike/logs/`
- `runtime-revive/playcover-spike/mock-server/logs/`

日志可能包含客户端标识和请求数据。提交问题时只提供必要、已脱敏的片段，详见[隐私与分发说明](docs/privacy.md)。

</details>

## 参与开发

欢迎通过 [Issues](https://github.com/Yibael/archercat-friends-revival/issues) 提交可复现的问题，或通过 Pull Request 改进启动流程、mock 响应和测试。

报告问题时，请提供 macOS、PlayCover 版本、复现步骤，以及已脱敏的错误信息。请将运行观察与推测分开描述；日志中的成功响应不能代替实际功能验证。

### 本地检查

以下检查不会启动游戏：

```sh
uv sync --locked --python 3.12
uv run --locked --no-sync python -m unittest discover -v
uv run --locked --no-sync python tools/check_distribution.py
bash -n Start.command
bash -n runtime-revive/playcover-spike/launch-player.sh
```

提交前审查改动，按需更新 `PUBLIC_FILES.txt`。新增或删除文件时，先用 `git add <具体路径>` 将这些变更加入暂存区，使 Git 跟踪列表与公开清单一致，再重新生成分发校验清单：

```sh
uv run --locked --no-sync python tools/check_distribution.py --refresh
uv run --locked --no-sync python tools/check_distribution.py
git diff --check
```

清单更新不会自动纳入额外文件。不要提交运行日志、缓存、个人存档或凭据；具体排除项见[隐私与分发说明](docs/privacy.md)。

### 提交约定

提交应聚焦一个目的，说明变更带来的行为及必要验证。提交信息使用 Conventional Commits 风格，例如：

```text
fix(launcher): preserve the mock until the owned game exits
docs(readme): clarify first-run requirements
```

## 文档与来源

| 文件 | 内容 |
| --- | --- |
| [测试记录](docs/testing.md) | 实测结果、已知问题和后续验收范围 |
| [隐私与分发](docs/privacy.md) | 分发排除项、隐私检查与扫描边界 |
| [来源记录](PROVENANCE.json) | IPA、项目图标的来源及处理记录 |
| [第三方依赖](vendor/SOURCES.json) | 官方 Frida wheel 的来源和 SHA-256 |
| [分发清单](PUBLIC_FILES.txt) | 明确允许提交的文件 |
| [文件校验](DISTRIBUTION.json) | 分发文件的 SHA-256 |

## 致谢与许可

感谢 [PlayCover](https://github.com/PlayCover/PlayCover)、[Frida](https://frida.re/) 和 [uv](https://github.com/astral-sh/uv) 提供运行与开发工具。

项目代码目前尚未声明开源许可证。ArcherCat Friends 的名称、客户端、图标与美术资源归原权利人所有；本项目是非官方实验，不代表原开发商。随仓库提供的 Frida wheel 保留其原始许可证和元数据。
