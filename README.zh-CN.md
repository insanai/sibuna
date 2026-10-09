<!-- English source SHA-256: 0e595d6fb27cba412aeae226ee13400d0d2eb66ac54aef03dace51a4a43911fb -->
<h1 align="center">sibuna</h1>
<p align="center">通过浏览器工作量证明保护网站，并提供可选的管理控制台。</p>
<p align="center">
  <a href="#features">功能</a> ·
  <a href="#quickstart">快速入门</a> ·
  <a href="#console">控制台</a> ·
  <a href="#how-it-works">工作原理</a> ·
  <a href="#documentation">文档</a>
</p>

<!-- language-navigation -->
<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ko.md">한국어</a> · <a href="README.ja.md">日本語</a> ·
  <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> ·
  <a href="README.hi.md">हिन्दी</a> · <a href="README.ar.md">العربية</a>
</p>

**Sibuna 帮助网站和 API 抵御不需要的机器人流量。** 它可以将请求转发给应用，也可以配合 Caddy、nginx 或 Traefik 等现有代理使用。

发送请求通常很便宜，处理请求却可能让应用付出更多计算成本。Sibuna 要求客户端先解一道计算题，再获得访问权限。这种设计让生成证明所需的计算量大于验证证明的计算量，使自动化客户端也承担一部分访问网站的成本。

计算也消耗能源，但实际用量取决于硬件和配置。工作量证明增加的是访问成本，并不能证明访问者是人，也不能阻止所有攻击。已获准访问的客户端可以凭签名会话再次访问，不必为每个请求重新解题。请通过访问规则和本地速率限制控制它们之后可以发送的请求。

<a id="features"></a>

## 功能

- **一个可执行文件：** 包含引擎、嵌入式存储、浏览器求解器和控制台资源。
- **原生安装包：** 支持 Linux、macOS 和 Windows。浏览器求解器使用 WebAssembly。
- **浏览器挑战：** 可配置 Hashcash 或顺序工作量证明，完成后获得签名会话。
- **访问策略：** 根据地址、路径、请求头和 User-Agent 放行、挑战或拒绝请求。
- **应用层检查：** 内置 SQL 注入、XSS 和路径遍历检测。
- **可选的 OWASP CRS：** 支持签名规则更新、Audit 和 Enforce 模式、隔离测试与回滚。
- **本地速率限制：** 控制突发和持续流量，也可为单条规则配置限额。
- **管理控制台：** 查看流量、按国家采样的活动和已记录的事件，并编辑策略。
- **集群支持：** 另行从源码构建的集群版本通过 Zaxonlite 复制策略和信誉数据。

<a id="quickstart"></a>

## 快速入门

[下载适合平台的发行包](https://github.com/insanai/sibuna/releases/tag/v0.3.5)。默认安装包包含存储和控制台支持。使用 `--console` 启动控制台。

| 平台 | 安装包 | 要求 |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 或更高版本；静态链接 musl |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 或更高版本；静态链接 musl |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 15 或更高版本 |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 15 或更高版本 |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2019 或更高版本；原生 `sibuna.exe` |
| FreeBSD x86-64 | `sibuna-0.3.5-freebsd-15.1-amd64.pkg` | FreeBSD 15.1; CLI 软件包 |
| OpenBSD x86-64 | `sibuna-0.3.5.tgz` | OpenBSD 7.9; CLI 软件包 |

macOS 构建未签名。每个安装包都包含许可证、源码链接和构建清单。使用前，请对照 `SHA256SUMS` 校验压缩包。

Debian/RPM 软件包支持 Linux x86-64 和 ARM64；Arch `sibuna-bin` 支持 x86-64。FreeBSD 15.1 和 OpenBSD 7.9 软件包支持 x86-64，并安装 CLI。Linux 软件包包含默认停用的可选 systemd 服务。BSD 软件包不创建服务、账户或状态。这些是上游下载；社区仓库接纳需另行审核。发行版还包含 Homebrew 源码 formula 和 Helm chart。安装、验证、私密状态、升级及 Kubernetes 设置请参阅[软件包运维指南](https://insanai.github.io/sibuna/zh-hans/book/operations.html)。

在 Linux x86-64 上，假设应用监听 3000 端口：

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.5/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.5/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

打开 `http://127.0.0.1:8080` 即可在本地试用。部署公开网站时，请由可信入口终止 HTTPS，并将 Sibuna 的监听地址限制在私有网络内。Caddy 和 nginx 的配置方法见[部署指南](https://insanai.github.io/sibuna/zh-hans/book/operations.html)。

默认模式为 `reverse_proxy`。如果入口代理负责转发请求，只向 Sibuna 查询访问决策，请使用 `--mode forward_auth`。指南包含这两种配置。Shield 的内置检查默认启用。若只需要访问控制、不需要该检查器，请使用 `--gate`。通过 `--policy-file <file>` 选择访问规则，也应为无法运行浏览器挑战的 API 客户端和健康检查配置规则。

在 Windows 上，解压 ZIP 后在 PowerShell 中运行 `.\sibuna.exe --help`。按 Ctrl+C 停止程序。请使用 Windows ACL 限制对种子、凭据和数据文件的访问。

<a id="build-from-source"></a>

### 从源码构建

请使用 **Zig 0.17.0**。仓库中提供了固定工具链的校验和及依赖源码信息。

```sh
git clone git@github.com:insanai/sibuna.git
cd sibuna
python3 tools/prepare_build.py
zig build -Doptimize=safe -j2
```

可执行文件位于 `zig-out/bin/sibuna`。集群构建使用 `-Dcluster=true`，并需要 OpenSSL 3。构建检查见 [CONTRIBUTING.md](CONTRIBUTING.md)。

<a id="enable-owasp-crs"></a>

### 启用 OWASP CRS

CRS 默认关闭。下载并验证受支持的签名发行版，然后先使用 Audit 模式。在该模式下可以查看检测结果，而不执行 CRS 拒绝决策：

```sh
./sibuna crs check --version 4.30.0 --output ./crs-candidate
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --crs-mode audit --crs-dir ./crs-candidate
```

请使用新的候选目录。检查候选规则不会改变正在运行的守护进程。CLI 和控制台都可以准备更新、审查变更并选择已验证的候选规则。测试应用的正常流量并审查排除项之后，再启用 Enforce。更新、回滚、请求体限制及检查不完整时的处理方法见 [CRS 指南](https://insanai.github.io/sibuna/zh-hans/book/operations.html)。Forward-auth 必须使用 `--crs-profile headers`；它无法看到完整的应用请求体。

<a id="console"></a>

## 控制台

控制台与引擎在同一个可执行文件中运行。请先停止守护进程，再初始化管理员账户：

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

打开 `http://127.0.0.1:19446/console/` 并修改临时密码。[运维指南](https://insanai.github.io/sibuna/zh-hans/book/operations.html)介绍 HTTPS 访问、GeoIP 导入和 CRS 更新。若要同时启用 CRS 检查，请在命令中追加上面示例的 CRS 参数。

![Sibuna 控制台的地球、请求时间线及观测覆盖情况](docs/readme/images/console-globe.jpg)

地球展示过去一分钟内按国家采样的活动。标记表示国家的大致位置，箭头指向配置的服务器位置。它们并不表示单条实时连接。GeoIP 需要单独导入数据集。使用 `--console-location <latitude,longitude>` 设置服务器在地球上的位置。

<details>
<summary>流量概览、策略编辑器和事件调查</summary>

**流量概览** — 查看请求结果、观测时间窗口和实时更新。

![Sibuna 控制台流量概览，显示放行、挑战和拒绝请求的计数](docs/readme/images/console-dashboard.jpg)

**策略编辑器** — 示例为结账页面的挑战规则，明确列出匹配条件和配置。

![Sibuna 控制台策略编辑器，显示结账页面挑战规则的草稿](docs/readme/images/console-policy-editor.jpg)

**事件调查** — 查看已记录的证据和经过脱敏、长度受限的请求头。

![Sibuna 控制台事件证据，显示脱敏后的请求头和响应状态](docs/readme/images/console-incident.jpg)

</details>

这些截图来自运行 v0.2.0 的评审节点，由 Chrome 截取。流量和 GeoIP 映射均为测试数据。图中的计数不是基准测试结果。

<a id="how-it-works"></a>

## 工作原理

请求可能被放行、要求完成挑战或被拒绝。完成挑战的访问者会获得签名会话。之后的请求仍需通过适用的策略检查和速率检查。

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="完成计算题，获得签名会话；后续请求仍需检查规则">
</picture>

Gate 检查访问规则、会话和本地速率限制。Shield 在此基础上增加内置攻击检查器。原生 CRS 需要单独配置。先使用 Audit 查看检测结果，再启用 Enforce。

<details>
<summary>Gate、Shield 与 Sibuna 的内部模块</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="Gate 和 Shield 的请求决策：放行、挑战或阻止">
</picture>

图中展示的是 Gate 和 Shield 的内置检查。可选的 CRS 增加自己的检查流程。有效会话不会绕过适用的攻击检查或请求限制。

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="Sibuna 内部各模块的职责">
</picture>

各模块分别负责网络、证明、策略、本地状态和管理功能。[技术手册](https://insanai.github.io/sibuna/zh-hans/book/)介绍了它们的职责。

</details>

<a id="deployment-limits"></a>

### 部署限制

Sibuna 的私有监听端口使用 HTTP/1.1。公网 TLS 和 HTTP/2 由入口代理处理。Forward-auth 检查入口代理提供的元数据。反向代理模式下的完整 CRS 检查受到配置的请求体和工作量限制。内置检查器覆盖请求体的前 8 KiB。关闭 CRS 时，上传数据采用流式传输。WebSocket 消息会直接转发，不进行内容检查。
完整 CRS 默认限制请求为 4 MiB、响应为 1 MiB，并缓冲请求体和响应体以供检查。Enforce 会拒绝检查不完整的请求。在启用前，请针对应用审查这些限制和流式传输例外。

速率限制按节点独立计算。Sibuna 不提供针对大规模网络流量攻击的防护。控制台的严格性能目标尚未正式通过。在生产应用旁启用控制台之前，请阅读[部署限制和测量结果](https://insanai.github.io/sibuna/zh-hans/book/operations.html)。

<a id="benchmarks"></a>

## 基准测试

技术手册为每次测试记录源码版本、配置和主机信息。这些测量展示某一种工作负载下的请求成本，并不衡量同等防护能力或机器人识别准确率。

<a id="three-product-comparison"></a>

### 三款产品的比较

这次测试于 2026 年 10 月 4 日比较了 **Sibuna v0.2.0**、Anubis 1.27.0 和 BunkerWeb 1.6.15。服务端与请求生成器运行在不同的物理主机上。每款产品使用四个 CPU、64 个连接和同一个 Caddy 源站，未启用挑战和管理界面。表中为五次测试的中位数。

| 配置 | 正常 GET（req/s） | p99（ms） | 8 KiB JSON POST（req/s） | p99（ms） |
| --- | ---: | ---: | ---: | ---: |
| 直接访问源站 | 70,759 | 4.67 | 13,719 | 9.01 |
| Sibuna Gate | 71,270 | 4.12 | 13,719 | 9.16 |
| Anubis | 28,277 | 7.50 | 13,718 | 9.20 |
| BunkerWeb，CRS 关闭 | 13,617 | 8.27 | 12,300 | 8.94 |
| Sibuna Shield | 70,909 | 4.06 | 13,719 | 9.08 |
| BunkerWeb，CRS 开启 | 2,730 | 32.73 | 797 | 98.42 |

表中 BunkerWeb 的 CRS 配置检查范围比 v0.2.0 的 Shield 更广。Sibuna v0.3.0 增加了原生 CRS；这次比较是在该引擎加入之前进行的。两台主机都是共享容器，CPU 频率和其他主机活动未受控制。

<a id="native-crs-in-v030"></a>

### v0.3.0 的原生 CRS

这次单独测试使用八个仪表板、为产品分配四个 CPU，并从另一台主机建立 16 个连接。表中为五轮测试的请求速率中位数。内置检查器未启用。

| 工作负载 | CRS 关闭（req/s） | Audit，偏执级别 1（req/s） | Audit，偏执级别 2（req/s） |
| --- | ---: | ---: | ---: |
| 小型 GET | 47,311 | 10,787 | 7,423 |
| 8 KiB JSON POST | 13,726 | 1,151 | 799 |
| 16 KiB multipart 上传 | 6,704 | 4,248 | 2,887 |

在偏执级别 1 下，这三种工作负载的 p99 延迟分别为 2.34 ms、23.43 ms 和 6.34 ms。各 CRS 配置的进程 RSS 峰值为 133.8–140.5 MiB。没有任何测量请求触及工作量限制。测试使用干净的源码版本 `d461e7f`。其请求内容和并发数与三款产品的比较不同，因此两张表不能作为条件一致的对照测试。

范围、CPU、内存、Enforce 结果和复现命令见[基准测试记录](benchmarks/results/README.md)。这些数据并不代表单独的 console-impact 性能门槛已经通过。

<a id="documentation"></a>

## 文档

- [技术手册](https://insanai.github.io/sibuna/zh-hans/book/)：概念、算法、示例和测量结果。
- [白皮书（英文）](https://insanai.github.io/sibuna/whitepaper/)：架构、证明和设计细节。
- [运维指南](https://insanai.github.io/sibuna/zh-hans/book/operations.html)：安装和部署。
- [参考手册](https://insanai.github.io/sibuna/zh-hans/book/reference.html)：CLI 和协议细节。
- [设计讨论（英文）](https://insanai.github.io/sibuna/sid/)：决策和工程约定。
- [贡献指南（英文）](CONTRIBUTING.md)：源码构建和检查。

<a id="other-software-to-consider"></a>

## 也可考虑的软件

- [Anubis](https://github.com/TecharoHQ/anubis)：通过浏览器挑战减少爬虫流量。
- [BunkerWeb](https://github.com/bunkerity/bunkerweb)：集成 nginx、ModSecurity、CRS 和机器人挑战。
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)：通过连接器使用的 WAF 引擎。
- [Coraza](https://github.com/corazawaf/coraza)：支持 ModSecurity 规则和 CRS 的 Go WAF 库。
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)：供 WAF 引擎使用的攻击检测规则。

这些项目覆盖网站防护的不同方面。Sibuna 执行经过签名的官方 CRS 发行版。插件、Lua 及其他 ModSecurity 规则集不在其支持范围内。

<a id="license"></a>

## 许可证

引擎采用 **LGPL 3.0**，控制台及其 WebAssembly 界面采用 **AGPL 3.0**。默认可执行文件包含两者，按 AGPL 3.0 分发。使用 `-Dconsole=false` 可以构建不含控制台的引擎。

[LICENSE](LICENSE) 说明授权范围，[LICENSES](LICENSES) 包含完整条款，[NOTICE](NOTICE) 列出依赖。各发行标签下均提供源码和构建脚本。

需要其他授权条款的企业可以联系 Vikrant Rathore 和 Ronak Rathore。第三方库及资料保留各自的许可证。
