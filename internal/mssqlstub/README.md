# nuclei 集成妥协说明

## 当前妥协

### 1. utils 降级
- **文件**: go.mod
- **内容**: `replace github.com/projectdiscovery/utils v0.11.1 => v0.10.1`
- **原因**: nuclei v3.8.0 的 `internal/runner/runner.go` 使用 aurora v2，而 utils v0.11.1 的 update 子包升级到了 aurora v4，类型不兼容
- **何时删除**: nuclei 升级 runner.go 的 aurora import 从 v2 到 v4 后
- **要改的 nuclei 文件**: `internal/runner/runner.go` (import, colorizer 类型), `pkg/templates/log.go` (Colorizer 类型), `internal/colorizer/colorizer.go`

### 2. mssql 驱动空壳
- **文件**: go.mod + internal/mssqlstub/
- **内容**: `replace github.com/microsoft/go-mssqldb v1.9.2 => ./internal/mssqlstub`
- **原因**: chainreactors SDK 依赖 denisenkom/go-mssqldb，nuclei JS 引擎依赖 microsoft/go-mssqldb，两者都注册 "mssql" 驱动导致冲突
- **何时删除**: projectdiscovery 统一使用同一个 mssql 包路径后

### 3. cdncheck 降级
- **文件**: go.mod
- **内容**: cdncheck v1.2.38 → v1.2.37（连锁反应，自动降级）
- **原因**: cdncheck v1.2.38 依赖 retryabledns v1.0.115，后者需要 utils ≥ v0.11.0，与妥协 1 冲突
- **何时删除**: 妥协 1 删除后自动恢复

## 升级检查清单

升级 nuclei 或 cdncheck 时，按顺序执行：

1. `go get -u github.com/projectdiscovery/nuclei/v3/lib@latest`
2. 尝试 `go build ./...`
3. 如果报 aurora 冲突 → 妥协 1 仍需保留，删除最新版 nuclei 继续等
4. 如果报 mssql 冲突 → 查看是否同一包路径，是则删除妥协 2
5. 如果编译通过 → 删除所有 replace，删除本目录
