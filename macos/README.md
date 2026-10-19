# macOS 管理员命令行客户端原型

此目录实现一个通过 `sudo` 启动的用户态客户端：`utun` 接收 IPv4 包，
用户态维护会话，每个原始五元组使用独立的 connected UDP socket 与现有
Linux natcap 服务端通信，再将回包恢复为原始目标的 IP/TCP/UDP 包写回 `utun`。

这是第一阶段原型，尚未完成 macOS 编译和真实服务端联通验收，不能视为
与 Linux 客户端功能、性能完全等价的发行版本。它不是 KEXT，也不通过
`kextload`、`kmutil` 或 `insmod` 加载。

## 当前范围

| 能力 | 当前实现 |
| --- | --- |
| IPv4 TCP 透明接管 | 已实现协议和事件循环；TCP 栈保留在操作系统中 |
| TCP 传输 | 使用已有 TCP-over-UDP 格式，对应服务端配置中的 `tcp_encode=U` |
| IPv4 UDP 透明接管 | 已实现，使用 UDP-over-UDP，对应 `udp_encode=U` |
| 认证元数据 | TCP ALL option；UDP 协议 1 携带 `user_hash` 和 MAC |
| 载荷编码 | 仓库相同的 256 字节替换表和 seed，包括逆向还原 |
| TCP option 空间不足 | 压缩 NOP/EOL 填充，在同一个 SYN 中携带完整认证信息和原有选项 |
| UDP 确认 | 消费 `NATCAP_E_MAGIC_A`，确认后停止附加初始化头 |
| 端口选择 | 固定端口、原始目标端口、每会话随机端口 |
| `sproxy` | 可选 TCP 标记，要求服务端配套运行 natcapd-server |
| 分流 | 显式指定最多 128 个 IPv4 CIDR；全局 IPv4 路由拆为两个 `/1` |
| 退出清理 | SIGINT/SIGTERM/SIGHUP；按成功添加记录回收路由 |

当前会话上限为 512，实际可用数量还受进程文件描述符限制。UDP 空闲 20 秒回收；
TCP 空闲 2 小时回收，见到 FIN 后保留最多 120 秒，RST 后最多 10 秒。
新连接在表满时丢包，不驱逐其他仍有效的连接。

TCP SYN 中的完整认证 option 占 20 字节，留给原有 TCP 选项的空间为 20 字节。
常见 macOS 的 24 字节选项去除 NOP/EOL 填充后可放入这个空间，保留 MSS、窗口缩放、
时间戳和 SACK 的值。若去除填充后仍超过 20 字节，客户端会明确报错并丢弃该 SYN；
不会静默删除协商选项，也不会发送前导 SYN。

尚未实现：原生 TCP 出口及 UDP-over-TCP、HTTP confusion、peer/multipath、
多服务端分组和故障切换、ipset/CN 地址库及域名自动学习、自动 DNS 策略、
Linux 网关转发和完整 QoS。IPv6 没有接管；内层 IPv4 分片、ICMP 等协议丢弃，
因此不能使用 `ping` 验收。外层 UDP 的校验和、NAT 和分片重组由系统 socket 栈处理。

`--no-encryption` 以外的默认编码仅为现有协议的兼容字节替换，不能提供现代
加密隧道的机密性、完整性或服务端身份验证。

## 编译和启动

在目标 Mac 上安装 Xcode Command Line Tools 后运行：

```sh
make -C macos
make -C macos test
```

`make` 在 Linux 上也能编译协议核心、参数解析和公共事件循环；实际创建 `utun`
的分支只在 macOS 下编译。Linux 构建的二进制仅提供离线参数检查和帮助，不能接管流量。

先选择一个实际测试目标的 `/32`。下列服务端 IP、目标 IP 和 MAC 均为示例，
需替换为自己的服务端、测试目标和获授权的客户端身份：

```sh
./macos/build/natcap-macos --check-config \
    --server 192.0.2.10 --port 65535 \
    --mac 02:11:22:33:44:55 --user-hash 0 \
    --route 203.0.113.20/32

sudo ./macos/build/natcap-macos \
    --server 192.0.2.10 --port 65535 \
    --mac 02:11:22:33:44:55 --user-hash 0 \
    --route 203.0.113.20/32
```

`--server` 接受 IPv4 地址；MAC 是协议里的客户端身份，不会修改物理网卡的 MAC。
`--port 65535` 每个会话选择一个随机服务端端口；`--port 0` 保留原始目标端口。
服务端防火墙必须允许所选端口范围内的外层 UDP，并具有现有 natcap 所需的转发/NAT 配置。
这一模式相当于 Linux 客户端使用 `server 0 IP:PORT-e-U-U`。

其他参数：

```text
--seed 0            与服务端 seed 的低 8 位一致，默认 0
--no-encryption     关闭现有 natcap 载荷编码
--udp-protocol 1    默认值，使用含认证信息的 24 字节初始化头
--udp-protocol 0    使用 Linux 旧式 12 字节初始化头，不携带 UDP 身份
--sproxy            请求服务端 natcapd TCP 代理，默认关闭
--mtu 1200          默认值，允许范围 576..1400
--route CIDR       可以重复；必须填写规范网络地址，不能带主机位
```

需要接管全局 IPv4 时，可以显式指定 `--route 0.0.0.0/0`。
程序将其展开为 `0.0.0.0/1` 和 `128.0.0.0/1`，保留原有默认路由；
系统中更具体的路由仍然优先，因此这不是“禁止所有直连”的策略。
程序不更改系统 DNS 设置；访问未接管的 DNS 地址仍由原有网络完成。
服务端对 UDP/53 的目的 DNS 重写与现有服务端行为一致。

## 路由和生命周期

启动时先查询服务端的物理出口。若服务端没有现有主机路由，则添加固定出口主机路由，
避免服务器连接再次进入 `utun`。随后配置内核自动分配的 `utunN`，使用
`198.18.99.1` / `198.18.99.2` 作为本地/对端地址，再添加指定的 CIDR。
已有精确路由导致添加失败时中止，并回收本次已成功添加的路由。
不要在已有路由/VPN 使用该地址对的 Mac 上启动此原型。

程序使用 `/var/run/natcap-macos.lock` 防止多个实例同时管理路由，不修改 PF
规则、不启用网关转发。它以管理员权限在前台运行，每 30 秒输出会话和报文计数。
Ctrl-C 退出时清理本次添加的路由并关闭 `utun`。锁文件保留，文件锁在退出时释放。

强杀、崩溃或断电不能保证执行退出清理；尤其需检查遗留的服务端主机路由。
网络切换、休眠恢复和原出口失效后的自动恢复尚未实现，需要停止并重新启动。
不应在原型运行期间由其他程序替换它管理的路由。

## 线协议依据

实现对照当前仓库源文件，而不是仅参考 README 中的图：

- `../natcap.h`：魔数、TCP option 布局、UDP type/ENC 标志。
- `../natcap_common.c:natcap_tcpopt_setup()` / `natcap_tcp_encode()`：
  NATCAP option 放在原 TCP options 前；认证 hash 按网络字节序传输。
- `../natcap_common.c:natcap_tcp_decode()`：`NATCAP_TCPOPT_SYN` 标记会将序号改为
  特殊标记值。Mac 客户端不使用这个前导包机制，以免现有服务端在 TCP-over-UDP
  路径提前转发前导 SYN、使目标确认错误的 TCP 序号。
- `../natcap_common.c:natcap_data_encode()` / `natcap_data_decode()`：替换表及 seed。
- `../natcap_client.c:natcap_client_post_out_hook()`：TCP-over-UDP 将 TCP 前 4 字节
  端口移入外层 UDP 头；UDP payload 为 `ffff0099 + TCP[4:]`，不是一个完整 IP 包。
- `../natcap_server.c:natcap_server_pre_in_hook()`：恢复 TCP 端口并重新计算校验和；
  因此客户端允许系统 UDP socket 选择源端口，以独立 socket 保存原五元组映射。
- `../natcap_server.c:natcap_udp_reply_cfm()` 及 UDP pre-ct 分支：
  初始化报文、确认包和回包载荷。原型一直使用 TYPE2 初始化报文，服务端确认前
  可重复发送，避免依赖单次初始化包到达。

## 验证与验收

```sh
make -C macos test
make -C macos sanitize
```

`test` 包括固定协议向量、认证字段字节序、256 种 seed 的全字节载荷、
回包 IP/TCP/UDP 校验和、macOS SYN 选项压缩、边界长度、畸形报文和命令行参数测试。
`sanitize` 使用 ASan/UBSan 检查协议解析器。

事件循环集成测试用 datagram socketpair 代替 `utun`、回环 UDP socket 代替服务端，
验证真实 UDP 收发、五元组隔离、回包注入和 UDP 确认。若 Linux 宿主机已经加载
natcap，该测试默认跳过，以免本机内核模块接管其测试报文。支持非特权 user/network
namespace 的 Linux 可在独立网络命名空间运行：

```sh
make -C macos test-runtime-isolated
```

此目标还运行真实 Linux TCP 栈测试：将完成编码和解码的 macOS 风格 SYN 注入
独立命名空间的回环 TCP 监听端，核对 SYN-ACK 确认序号与时间戳回显。
这能检查 TCP 协商与校验和，但不等同于加载 natcap 服务端模块后的实机互通。

测试不会加载/卸载宿主机模块，也不改宿主机路由、防火墙或服务端配置。

这些检查不证明 macOS SDK 编译成功或与真实 Linux 服务端互通。下一步的必需验收是：

1. 在目标 macOS/CPU 上编译并通过本目录测试，确认 `utun` 创建、IPv4 配置和正常退出回收。
2. 用一个目标 `/32` 和真实 Linux natcap 服务端完成 TCP 握手、HTTPS 下载/上传、UDP DNS 查询。
3. 抓取 Mac `utunN`、物理出口和服务端包，核对带认证信息和原有选项的单个 SYN、重传、
   UDP 初始化/确认、载荷编码和 FIN/RST。
4. 验证服务端要求的 MAC/hash/seed 和可选 sproxy；用丢包、乱序和不同 MTU 检查大包路径。
5. 验证失败启动、Ctrl-C、TERM、已有路由冲突和遗留路由处置，再扩大接管范围。

## TCP 握手故障排查

初版 `63f6ca9` 会在 macOS SYN 的选项空间不足时发送前导 SYN。抓包已确认某些
现有服务端将其转发后，SYN-ACK 确认的是特殊标记序号，而不是客户端真实初始序号，
随后客户端发送 RST。该问题已通过在单个 SYN 中压缩填充并携带完整元数据修复，
不需要修改服务端或更改客户端启动参数。

排查时先使用一个固定服务端端口。下面以 UDP/6553 和目标 `203.0.113.20` 为例，
在服务器上以 root 抓取外层 UDP 和解封装后的目标流量：

```sh
tcpdump -i any -nn -s 0 -U -w /tmp/natcap-macos.pcap \
    'udp port 6553 or host 203.0.113.20 or icmp'
```

在 Mac 上启动客户端后，另开终端测试目标的 HTTP 服务；目标和端口按实际服务替换：

```sh
curl -4 -v --noproxy '*' --connect-timeout 10 --max-time 20 http://203.0.113.20/
```

停止抓包后用 `tcpdump -nn -vvv -X -r /tmp/natcap-macos.pcap` 查看。
外层 TCP-over-UDP 载荷以 `ff ff 00 99` 开头，其中后续 4 字节是真实 TCP 序号，
再后面 4 字节是确认序号。首次 SYN-ACK 应确认客户端 SYN 的初始序号加 1。
抓到 UDP 回包但紧接客户端 RST 时，应先检查这个关系。

## 与 Netfilter 的区别

macOS 的 PF 提供状态防火墙、NAT 和重定向规则，但没有本仓库使用的
`nf_register_net_hooks()`、Linux conntrack 和 `sk_buff` 模块接口。
旧式 IP filter KEXT 更接近内核 hook，但仍需重写 Linux 依赖，且现代 macOS 的
加载和发行限制明显不同于 Linux。

- [Apple：PF 不属于稳定产品 API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)
- [Apple XNU：传统 IP filter 接口](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/kpi_ipfilter.h)
- [Apple：现代 macOS 的内核扩展加载限制](https://support.apple.com/en-ca/guide/security/sec8e454101b/web)
- [Apple XNU：utun 接口定义](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.h)

若后续改为面向普通用户分发的 App，可将独立于 Linux/macOS API 的
`natcap_codec.c` 作为协议核心接入 Packet Tunnel Provider；当前实现不包含 App 或系统扩展工程。
