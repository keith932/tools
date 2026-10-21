# tools

## CrowdStrike Falcon Linux 安装与入组

在堡垒机选择需要部署的 Linux 服务器，账号使用 `root`、模块使用 `Shell`。
替换 API 凭据后，将下面完整一行作为快捷命令执行：

```bash
curl -fsSL --retry 3 https://raw.githubusercontent.com/keith932/tools/main/falcon-host-install.sh -o /root/falcon-host-install.sh && FALCON_CLIENT_ID='你的ClientID' FALCON_CLIENT_SECRET='你的ClientSecret' bash /root/falcon-host-install.sh
```

### 运行条件

- 目标主机已有 Bash、curl、systemd，以及 Python 2.7 或 Python 3。
- 可以通过 HTTPS 访问 GitHub 和所属 CrowdStrike 云区域。
- API Client 具有 `Sensor Download: Read`、`Host groups: Read / Write` 权限。
- 如果租户要求安装令牌，还需要 `Installation Tokens: Read`。
- Client ID 是 OAuth API Client ID，不是客户 CID。凭据在运行时传入，仓库不保存凭据。
- 请按系统、架构和具体内核核对 Falcon 支持范围；先在各类系统上选一台验证。

### 脚本行为

- 先验证 API 凭据和目标组，再调用官方 `falcon-scripts v1.14.0` 下载匹配的 Sensor 并安装注册。
- 默认目标组为 `misc1`，组 ID 为 `f21f4746723b4e4994c26d8b566fcab2`。支持 static / staticByID，动态组会报错。
- 已有安装不升级、不重启、不覆盖 CID；健康检查通过后可补入组。
- 检查服务 active、RFM false 和非空 AID，再以当前主机的 AID 调用入组 API。
- 枚举目标组成员并交叉核对主机 `groups` 字段包含目标组 ID，才输出 `GROUP=VERIFIED_HOST_FIELD misc1`。
- 入组失败不卸载已安装的 Sensor，返回非零状态。安装成功与入组成功分别判断。
- 入组可能应用该组已有策略；脚本不会编辑策略、组规则或删除其他成员。
- 本地健康检查不能证明系统受到官方支持，也不能代替控制台在线、策略和威胁检测验证。

### 只读核查入组

下载后可以单独执行只读核查，不重新安装或修改组成员：

```bash
FALCON_CLIENT_ID='你的ClientID' FALCON_CLIENT_SECRET='你的ClientSecret' bash /root/falcon-host-install.sh --verify-group
```

输出包含脚本版本、AID 前 12 位、过滤成员查询结果、无过滤组成员查询结果和主机组字段。
不输出完整 AID、Client Secret 或 Bearer Token。

堡垒机可能保留输入的命令和执行记录。建议使用临时部署 API Client，完成后撤销；不要启用 shell tracing。

### 官方参考

- [Falcon Linux 安装脚本](https://developer.crowdstrike.com/falcon-sensor/scripts/bash/install/)
- [主机组 API](https://developer.crowdstrike.com/api-reference/collections/host-group/)

当前脚本已做离线模拟验证；租户里的实际入组问题仍需运行只读核查后确认。
