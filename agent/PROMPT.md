# Agent：OpenStack CVE vs openEuler

## 本工具职责边界

`os-cve-cache` **只**负责：

1. 从 OpenStack OSSA 拉取 CVE
2. 缓存进 SQLite（`data/cve.db`）
3. 按条件查询并输出 **标准 JSON**

**不要**在本程序里做 openEuler 对比或自动建 Issue。这些由 Agent 完成。

## 获取 JSON

```bash
go run ./cmd/os-cve-cache query --since 2024-01-01 --limit 100
# 或按组件
go run ./cmd/os-cve-cache query --component Nova --limit 50
```

`stdout` 仅为 JSON；日志在 `stderr`。

### JSON 契约

```json
{
  "count": 1,
  "items": [
    {
      "cve_id": "CVE-2026-71196",
      "title": "...",
      "summary": "...",
      "components": ["Glance"],
      "severity": "",
      "published_at": "2026-09-03T00:00:00Z",
      "refs": ["https://..."],
      "source": "ossa",
      "fetched_at": "2026-11-18T14:00:00Z"
    }
  ]
}
```

说明：

- `severity` 在 OSSA 源上常为空
- 无 CVE 编号的 OSSA 不会入库
- `components` 来自 Affects 组件名

## Agent 建议步骤

1. 运行 `query` 拿到 OpenStack CVE JSON
2. 对每个 `cve_id` / 组件，在 openEuler 侧检索是否已跟踪、已修复、已发公告
3. 产出差异表（缺失 / 版本差距 / 已覆盖）
4. 仅对确认缺口创建 Issue，附上 `cve_id`、`refs`、`summary`

## 刷新缓存

```bash
go run ./cmd/os-cve-cache fetch
```
