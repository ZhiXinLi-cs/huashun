# Banner 指纹识别系统

Go 实现的网络服务 Banner 指纹识别系统：接收一批网络扫描原始数据（`ip`、`port`、`banner`），识别出对应的**协议、软件与版本**。采用 **client + server** 架构，**Docker Compose 一键启动**。

## 架构总览

```
+----------------+   POST /fingerprint    +----------------------+
|     client     | ---------------------> |        server        |
| 读本地 JSON 文件 |                        | 规则加载 → 正则匹配     |
| 展示识别结果     | <--------------------- | （规则与代码解耦）      |
+----------------+     识别结果 JSON        +----------------------+
```

- **server**：长驻 HTTP 服务，提供 `POST /fingerprint`（批量识别）与 `GET /health`（健康检查）。
- **client**：一次性任务程序，读取本地 JSON 文件 → 发送 server → 表格展示识别结果。
- **识别引擎**：规则文件（`config/rules.yaml`）按 `priority` 降序匹配，首个命中的规则产出协议/软件/版本（正则捕获组取版本），再用全局 OS 特征填充 `os_hint`。**认不出统一返回 `protocol:"unknown"`，绝不报错、绝不崩溃**（含 panic 兜底中间件）。

代码分层：`Router → Handler → Service → Repository → Model`（`internal/` 下各一层，见目录结构）。

## 快速开始（Docker Compose 一键启动）

前置条件：安装 Docker 与 Docker Compose 插件。

```bash
docker compose up --build
```

启动后：

1. server 容器通过健康检查（周期请求 `/health`）进入 healthy 状态；
2. client 容器**等 server 健康后才启动**（`depends_on: condition: service_healthy`），读取 `data/samples.json` 发给 server 并打印识别结果；
3. client 完成后退出（一次性任务），server 保持运行。

```bash
# 查看 client 识别结果
docker compose logs client

# 查看服务状态（server 应为 healthy）
docker compose ps

# 停止
docker compose down
```

**换自己的数据**：替换 `data/samples.json`（挂载为只读卷），再次 `docker compose up` 即可。

**手动调试 server**：compose 中取消 `server` 的 `ports: "8080:8080"` 注释，即可从宿主机 `curl http://localhost:8080/health`。

## 本地运行（不依赖 Docker）

```bash
# 启动 server（规则文件路径可用环境变量覆盖）
go run ./cmd/server
# 或：RULES_FILE=config/rules.yaml SERVER_ADDR=:8080 go run ./cmd/server

# 另开终端跑 client
go run ./cmd/client
# 或：CLIENT_FILE=data/samples.json SERVER_URL=http://localhost:8080 go run ./cmd/client
```

## API

### POST /fingerprint（批量识别）

请求体为待识别数据数组：

```json
[
  {"ip": "192.168.1.10", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"},
  {"ip": "10.0.0.99", "port": 54321, "banner": "some totally unknown service"}
]
```

响应为与输入顺序一致的结果数组：

```json
[
  {"ip": "192.168.1.10", "port": 22, "protocol": "SSH", "product": "OpenSSH", "version": "8.9p1", "os_hint": "Ubuntu", "confidence": 0.95},
  {"ip": "10.0.0.99", "port": 54321, "protocol": "unknown", "product": "", "version": "", "os_hint": "", "confidence": 0}
]
```

字段说明：`protocol`（协议名大写：`SSH`/`HTTP`/`MySQL`/`Redis`/`FTP`，认不出为 `unknown`）、`product`（软件）、`version`（版本，取不到为空）、`os_hint`（操作系统线索，取不到为空）、`confidence`（置信度 0~1，按信号强弱分档）。

非法 JSON / 非数组请求体返回 `400 {"error":"invalid JSON body"}`；请求体上限 1MB。**任何输入都不会使服务崩溃**。

### GET /health（健康检查）

```
200 {"status":"ok"}
```

## 识别规则（与代码解耦）

规则全部在 `config/rules.yaml`，**程序代码不包含任何识别规则**，改规则无需重新编译：

```yaml
rules:
  - id: ssh-openssh
    protocol: SSH
    product: OpenSSH
    priority: 100        # 数字越大越先匹配
    confidence: 0.95
    patterns:            # 多条正则，任一命中即该规则命中；第 1 个捕获组 = version
      - '^SSH-\d+\.\d+-OpenSSH[_-]([^\s]+)'
```

- 支持协议：**SSH**（OpenSSH/Dropbear，兼容 `SSH-1.99` 前缀）、**HTTP**（nginx/Apache/Jetty）、**MySQL**（兼容纯版本号与 `\n` 后跟版本号的握手报文两种形态）、**Redis**（INFO 输出 / `+PONG` / `-NOAUTH` / `-ERR` 多信号，置信度分档）、**FTP**（vsFTPd/ProFTPD/Pure-FTPd/Microsoft FTP），以及全局 `os_hints` 操作系统特征。
- 新增协议：在 `rules.yaml` 加一条规则即可，server 重启后生效（容器内也支持用 volume 挂载覆盖 `/etc/fingerprint/rules.yaml`）。
- 规则正则一律用单引号包裹，YAML 不转义 `\d`、`\s`、`\b`。

## 生产级部署要点（Docker 交付设计）

| 评估点 | 实现 |
|---|---|
| 容器间访问收敛 | 自定义 bridge 网络；client 经 compose 服务名 `http://server:8080` 访问，不写死 IP；server 端口只在内部网络可见，不映射宿主机 |
| 真实健康检测 | server 定义 `healthcheck`（周期性请求 `/health`）；client `depends_on: condition: service_healthy` 真实等待健康状态 |
| 多阶段构建 | `golang:1.26-alpine` 编译（`CGO_ENABLED=0`、`-ldflags="-s -w"`）→ `alpine:3.20` 运行，最终镜像只含静态二进制与规则文件 |
| 容器权限收紧 | 镜像内以非 root 用户 `app` 运行；`cap_drop: ALL`、`no-new-privileges`、server 只读根文件系统 |
| 规则与代码解耦 | 识别规则独立于 `config/rules.yaml`，代码启动时加载，可 volume 覆盖 |

## 测试

```bash
go test ./...        # 单元测试：6 类协议识别 + unknown 兜底 + 顺序一致性
go vet ./...
```

## 目录结构

```
├── cmd/
│   ├── server/main.go        # server 入口：装配各层并启动
│   └── client/main.go        # client 入口：读 JSON → 发请求 → 打印
├── internal/
│   ├── router/               # Router 层：路由注册 + panic 兜底中间件
│   ├── handler/              # Handler 层：参数绑定、组装响应
│   ├── service/              # Service 层：识别引擎（正则匹配、OS 推断、unknown 兜底）
│   ├── repository/           # Repository 层：加载/编译规则文件
│   └── model/                # Model 层：输入/输出/规则数据结构
├── config/rules.yaml         # 识别规则（与代码解耦）
├── data/samples.json         # client 输入样例
├── Dockerfile.server         # server 镜像（多阶段构建）
├── Dockerfile.client         # client 镜像（多阶段构建）
└── docker-compose.yml        # 一键启动编排
```
