# OpenStackCVE / os-cve-cache

用 Go 从 [OpenStack Security Advisories](https://security.openstack.org/ossa/) 拉取 CVE，缓存到 **SQLite**，再按字段查询并输出 JSON，供 Agent 对比 openEuler。

程序只做：拉取 → 入库 → 查询 JSON。对比与建 Issue 见 [agent/PROMPT.md](agent/PROMPT.md)。

## 快速开始（Docker，推荐）

```bash
# 构建并启动 HTTP API（默认读 ./data/cve.db）
docker compose up -d --build

# 拉取/刷新 CVE（OSSA + NVD）
docker compose run --rm os-cve-cache fetch
# 或只拉 NVD
docker compose run --rm os-cve-cache fetch --source nvd

curl -s 'http://127.0.0.1:8080/api/cves?limit=5'
```

数据目录挂载：`./data` → 容器 `/data`。

## 本地运行（非容器）

```bash
cp config.example.yaml config.yaml
go mod tidy
go run ./cmd/os-cve-cache init-db
go run ./cmd/os-cve-cache fetch
go run ./cmd/os-cve-cache query --limit 5
```

## 命令

| 命令 | 说明 |
|------|------|
| `init-db` | 创建 `data/cve.db` 并建表 |
| `fetch` | 拉取 OSSA / NVD，按 `cve_id` 去重合并入库 |
| `query` | 多字段过滤，**stdout 只输出 JSON** |
| `serve` | 启动 Gin HTTP API（读 SQLite） |

### HTTP API（Gin）

```bash
go run ./cmd/os-cve-cache serve --addr :8080
```

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 健康检查 |
| GET | `/api/cves` | 列表/过滤：`cve_id` `component` `since` `severity` `limit` |
| GET | `/api/cves/:cve_id` | 按 CVE ID 查询单条 |

```bash
curl -s 'http://127.0.0.1:8080/api/cves?limit=5'
curl -s 'http://127.0.0.1:8080/api/cves?component=Ironic'
curl -s 'http://127.0.0.1:8080/api/cves/CVE-2026-115642'
```


### fetch 示例

```bash
# OSSA + NVD（按 lookback_days，cve_id 去重合并）
go run ./cmd/os-cve-cache fetch

# 只拉 NVD / 只拉 OSSA
go run ./cmd/os-cve-cache fetch --source nvd
go run ./cmd/os-cve-cache fetch --source ossa

# 单条 OSSA
go run ./cmd/os-cve-cache fetch --id OSSA-2026-038
```

NVD 可选环境变量 `NVD_API_KEY`（提高速率限制）。合并规则：同一 `cve_id` 合并 components/refs，文案优先 OSSA，severity 优先保留已有值（空则用 NVD CVSS）。

### query 示例

```bash
go run ./cmd/os-cve-cache query \
  --cve-id CVE-2026-71196 \
  --component Glance \
  --since 2024-01-01 \
  --limit 100

# 可选写文件（仍打印到 stdout）
go run ./cmd/os-cve-cache query --since 2026-01-01 --out result.json
```

日志一律输出到 **stderr**。

## 配置

见 [config.example.yaml](config.example.yaml)：

- `sqlite.path`：默认 `data/cve.db`
- `fetch.lookback_days`：默认 180
- `fetch.source`：一期仅 `ossa`

## 技术说明

- SQLite 驱动：`modernc.org/sqlite`（无 CGO）
- 无 CVE 的 OSSA 跳过入库
- 组件检索使用 `cve_components` 表
