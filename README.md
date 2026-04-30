# Codex Manager

一个面向多节点场景的可视化调度平台，用于统一管理注册任务、邮箱验证码通道、代理切换、云端仓库补货与本地库存。

> 仅可用于你拥有或已获得明确授权的系统环境。

## 致谢

本项目基于 [wenfxl/openai-cpa](https://github.com/wenfxl/openai-cpa) 开发，感谢原作者的贡献。上游仓库持续更新注册流程与功能修复，本 Fork 在同步上游业务代码的同时做了以下定制化调整。

## 与上游的区别

1. **移除鉴权机制** — `auth_core` 编译二进制回退至 v13.1.0 版本（不含 `check_global_license`、`read_license_file`、`get_stable_hwid` 及远程验证端点），通过 `auth_core_patch.py` 以纯 Python 实现 v14.0.0 新增的 `email_jwt`、`sys_node_allocate`、`sys_node_release` 接口，保留全部业务功能。
2. **品牌标识替换** — 启动日志、前端标题、导航栏等处的上游品牌替换为本项目标识。
3. **默认值替换** — 集群密钥 `wenfxl666` → `codex2026`、数据库名 `wenfxl_manager` → `codex_manager`、webhook 密钥 `wenfxl_secret_key` → `codex_secret_key`（已有配置文件不受影响，仅影响首次生成）。
4. **更新检查重定向** — 版本检查与更新下载链接指向本 Fork 仓库 `tvvshow/openai-cpa`。
5. **Docker 镜像** — 使用 `pestxo/wenfxl-codex-manager`，通过 GitHub Actions 自动构建（tag 触发）。
6. **上游项目链接保留** — 前端配置页面中指向上游独立项目（cloudflare_temp_email、freemail、cloud-mail、openai-cpa-email）的链接保持不变。

## 项目简介

本项目提供一个基于浏览器的控制台，后端采用 FastAPI，前端采用 Vue。你可以在一个面板里完成以下工作：

1. 配置多种邮箱通道并自动收取验证码。
2. 启动或停止常规模式、CPA 模式、Sub2API 模式。
3. 管理本地库存与云端库存，执行测活、补货、推送、导出。
4. 管理代理池（Clash/Mihomo 或自定义代理池），提高并发稳定性。
5. 在集群模式下统一查看节点状态与日志。

## 主要能力

1. Web 可视化控制台，支持登录鉴权、实时状态、日志流推送。
2. 多邮箱后端：`cloudflare_temp_email`、`freemail`、`cloudmail`、`mail_curl`、`luckmail`、`DuckMail`、`Gmail OAuth`、`本地微软邮箱`、`Temporam`、`Tmailor`、`Fvia` 等。
3. 多代理策略：单机代理、Clash 节点轮换、容器代理池、自定义原始代理池。
4. 多运行模式：
   - 常规量产模式
   - CPA 仓管模式（测活 + 补货 + 云端同步）
   - Sub2API 仓管模式（测活 + 补货 + 云端同步）
5. 本地库存管理：分页、筛选、批量导出、批量删除、推送状态同步。
6. 集群能力：主控/节点模式、节点日志回传、远程启停与统一提取。
7. 通知能力：支持 Telegram 推送任务结果与异常信息。

## 运行环境

1. Windows：建议 Python 3.12。
2. Linux/macOS 原生运行：建议 Python 3.11。
3. 容器部署：推荐使用 Docker（开箱即用，版本差异最小）。

## 快速开始（本地运行）

### 1) 安装依赖

```bash
pip install -r requirements.txt
```

### 2) 首次准备配置

首次启动会自动从 `config.example.yaml` 生成 `data/config.yaml`。

### 3) 启动服务

```bash
python wfxl_openai_regst.py
```

### 4) 打开控制台

```text
http://127.0.0.1:8000
```

默认密码：`admin`

## Docker 部署

### 方式一：本地持久化（默认）

1. 准备 `docker-compose.yml`（仓库已提供）。
2. 准备 `data/config.yaml`（可先启动一次自动生成）。
3. 启动：

```bash
docker compose up -d
```

4. 查看日志：

```bash
docker compose logs -f
```

5. 停止：

```bash
docker compose down
```

### 方式二：云数据库模式

使用 `docker-compose2.yml`，通过环境变量指定 MySQL：

- `DB_TYPE=mysql`
- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASS`
- `DB_NAME`

此模式适合无状态容器部署。

## 配置说明（重点项）

配置文件：`data/config.yaml`

### 基础项

1. `web_password`：控制台登录密码。
2. `email_api_mode`：邮箱后端选择。
3. `mail_domains`：邮箱域名池（逗号分隔）。
4. `default_proxy`：默认代理地址。

### 常规模式

`normal_mode`：

1. `target_count`：单批目标数量。
2. `sleep_min` / `sleep_max`：批次间隔。
3. `save_img_to_local`：是否保存 image2api 数据到本地库。

### CPA 模式

`cpa_mode`：

1. `enable`：是否启用。
2. `api_url` / `api_token`：云端接口与凭证。
3. `min_accounts_threshold`：库存阈值。
4. `batch_reg_count`：单次补货量。
5. `auto_check`：补货前是否先测活。
6. `threads`：巡检并发数。

### Sub2API 模式

`sub2api_mode`：

1. `enable`：是否启用。
2. `api_url` / `api_key`：云端接口与凭证。
3. `min_accounts_threshold`：库存阈值。
4. `batch_reg_count`：单次补货量。
5. `auto_check`：补货前是否先测活。
6. `threads`：巡检并发数。

### 代理池

1. `clash_proxy_pool.enable`：启用 Clash 管理。
2. `clash_proxy_pool.pool_mode`：容器代理池模式。
3. `clash_proxy_pool.api_url`：Clash 控制接口。
4. `raw_proxy_pool.enable`：启用原始代理池。
5. `raw_proxy_pool.proxy_list`：自定义代理列表。

## 项目结构（核心）

```text
.
├── wfxl_openai_regst.py     # 服务入口
├── global_state.py           # 全局状态与引擎实例
├── routers/                  # 路由层（系统、账户、服务、短信）
├── utils/
│   ├── core_engine.py        # 调度核心（模式主循环、并发执行）
│   ├── config.py             # 配置加载与热更新
│   ├── db_manager.py         # SQLite/MySQL 双引擎数据库适配
│   ├── proxy_manager.py      # Clash/代理池切换
│   ├── auth_core_patch.py    # v14 新增 API 的纯 Python 兼容实现
│   ├── auth_pipeline/        # 注册流程与认证流程
│   ├── email_providers/      # 邮箱后端实现
│   └── integrations/         # 外部平台集成（Sub2API、TG、短信等）
├── static/                   # 前端静态资源
├── index.html                # 控制台页面
├── config.example.yaml       # 配置模板
└── tests/                    # 回归测试
```

## 数据存储

默认使用 SQLite：`data/data.db`。

可切换 MySQL：

```yaml
database:
  type: "mysql"
  mysql:
    host: "127.0.0.1"
    port: 3306
    user: "root"
    password: ""
    db_name: "codex_manager"
```

## 测试

运行全部测试：

```bash
python -m pytest tests/ -v
```

运行单个测试文件：

```bash
python -m pytest tests/test_log_stream_cache.py -v
```

## 常见问题

### 1) 控制台打不开

1. 确认端口 `8000` 未被占用。
2. 确认进程已启动并查看控制台日志。
3. 容器部署时确认端口映射 `8000:8000`。

### 2) 收不到验证码

1. 检查邮箱后端凭证是否有效。
2. 检查代理是否影响邮箱通道连通性。
3. 检查域名配置与后端 API 可访问性。
4. 检查验证码重试参数（`max_otp_retries`）。

### 3) Clash 切换失败

1. 检查 `api_url`、`secret`、`group_name`。
2. 检查 `test_proxy_url` 实际可用。
3. 检查黑名单过滤是否过严。

### 4) 云端仓库补货异常

1. 检查 `api_url` / `api_token`（或 `api_key`）配置。
2. 检查阈值参数与线程参数。
3. 检查是否启用 `auto_check` 导致补货前清理过多无效项。

## 安全建议

1. 不要公开 `data/` 目录与数据库文件。
2. 不要在公共环境暴露控制台登录口令。
3. 将 API Token、邮箱密钥、代理密钥交由环境变量或安全配置管理。
4. 团队部署建议增加入口访问控制与审计日志。

## 许可与使用说明

本项目采用 `CC BY-NC 4.0`（署名-非商业）协议。禁止未授权商业化使用。二次分发或修改需保留原作者署名并标注来源。

上游仓库：[wenfxl/openai-cpa](https://github.com/wenfxl/openai-cpa)

如需查看完整协议，请阅读仓库内 `LICENSE` 文件。
