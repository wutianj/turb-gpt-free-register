# RoxyBrowser 无限窗口工具包 · 本项目适配说明

## 部署位置

```
tools/roxy-unlimited-windows/
  roxy-unlimited-windows/   原工具包（28 个文件）
  svc.ps1                   服务管理：start / stop / restart / status
  ADAPTATION-zh.md          本说明
```

## 已做适配

1. 中文目录路径兼容：原工具包用 `new URL(import.meta.url).pathname` 拼路径，
   在带中文的项目目录下会把 `%E6%9C%8D...` 原样当文件名。已将
   `roxy-api.mjs`、`mkprofile.mjs`、`diag-ext.mjs`、`diag-shim.mjs`、
   `diag-trace.mjs` 中的路径推导改为 `fileURLToPath(import.meta.url)`。
2. `/browser/create` 兼容本项目客户端请求体：
   - `name` → 工具包 `windowName`
   - `proxyInfo`（protocol/host/port/username/password）→ 工具包 `proxy`
   - `workspaceId` / `projectId` 会被忽略，不参与本地额度计算。
3. 2026-09-14 同步上游 wangshen233/roxy-unlimited-windows 最新版：
   - 新增 `paths.mjs` 路径自动发现、`roxy-open.ps1`/`show-window.mjs` 窗口还原、
     canvas/tz 诊断脚本，noise-ext 与内核指纹合成均更新；
   - 重新打上上述 1/2 两处兼容补丁；
   - 客户端（core/roxybrowser_client.py）新增每次创建环境随机语言/时区：
     `ROXY_RANDOM_LOCALE_ON_CREATE` + `ROXY_LOCALE_CHOICES`，由本地 API 展开为
     appLocale/acceptLang/timeZone 写入 lumi.conf，并记录进账号 creation_metadata；
   - 旧版本备份在 `tools/roxy-unlimited-windows/roxy-unlimited-windows.bak-20260914`。

## 指纹随机化验证（新版本实测）

每次 /browser/create 都会重新随机：computerName、macAddress、GPU、屏幕分辨率、
canvas/audio 噪声、hardwareConcurrency、os（Windows 10/11）；传入 locale 时
appLocale/acceptLang/timeZone 三者互相一致。每次启动还会通过 CDP 注入按档案
实例化的 canvas/audio 噪声扩展（noise-ext）。

## 启动服务

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\roxy-unlimited-windows\svc.ps1 -Action start -Port 50100
powershell -NoProfile -ExecutionPolicy Bypass -File tools\roxy-unlimited-windows\svc.ps1 -Action status
powershell -NoProfile -ExecutionPolicy Bypass -File tools\roxy-unlimited-windows\svc.ps1 -Action stop
```

服务默认监听 `http://127.0.0.1:50100`，与本项目 `config/roxybrowser.py` 的
`ROXY_API_BASE` 对齐。

## 注册任务切到本地无限 API

注意：本项目启动时 `.env` 会覆盖 `config/roxybrowser.py` 的默认值，
因此必须同时确认 `.env` 中的地址为 `http://127.0.0.1:50100`；否则请求会回到官方
`50000` 接口并再次触发“窗口额度不足”。

`config/roxybrowser.py` 中确认：

```python
ROXY_API_BASE = "http://127.0.0.1:50100"
ROXY_API_TOKEN = ""            # 本地服务不校验 token
ROXY_ONE_PROFILE_PER_ACCOUNT = True
ROXY_DELETE_PROFILE_AFTER_RUN = True
```

`.env` 至少应包含：

```dotenv
ROXY_API_BASE="http://127.0.0.1:50100"
```

`ROXY_WORKSPACE_ID` 与 `ROXY_PROJECT_ID` 仍可保留，本地服务会忽略它们，
只需保证客户端不因空 workspace 报错。

## 关键差异

- 本地服务直接读 `%APPDATA%\RoxyBrowser\chrome-bin` 内核和
  `%APPDATA%\RoxyBrowser\browser-cache`，不需要官方 App 在运行。
- 档案完全本地生成，不上传云端，不消耗官方团队 `maxWindowCount` 额度。
- 不支持官方工作台可见性、云同步、代理预检。

## 验证命令

```powershell
python .venv\Scripts\python.exe tools\roxy-unlimited-windows\smoke_test.py
```
