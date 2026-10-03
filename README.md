# privacy-erasure

员工档案隐私擦除库。由上层直接调用；业务状态与审计保存在 SQLite，备份保存在工作目录内的本地文件。仅依赖 Python 标准库（3.9+）。

## 核心机制：加密粉碎（crypto-shredding）

- 每个 worker 的 PII（姓名、SSN）用**专属随机密钥**加密后写入 `state.db`（当前档案与审计历史中的 PII 均为密文）。
- 密钥保存在独立的 `keystore.db`，**永不进入备份**。
- 擦除 = 销毁该 worker 的密钥 + 删除当前档案。此后该 worker 全部历史 PII 在主库、审计账本和**所有历史备份**中都只剩密文，即使持有全部受管文件也无法恢复。
- 非 PII（workerID、客户公司、州）与操作事实始终明文可读，合规审计不随档案消失。

## 工作目录布局

```
<workdir>/
  state.db      # 业务状态 + 审计账本 + 擦除/请求幂等台账
  keystore.db   # 每 worker 的 PII 密钥（不备份）
  backups/      # backup() 生成的备份文件
```

## API 速览

```python
from privacy_erasure import PrivacyErasureLibrary

lib = PrivacyErasureLibrary("/path/to/workdir")

# 登记 / 更新 / 读取
lib.register("w-001", "Alice", "111-22-3333", "Acme", "CA")
lib.update("w-001", name="Alicia", ssn="222-33-4444")
lib.get_profile("w-001")     # -> dict（明文 PII）；不存在 -> None
lib.get_history("w-001")     # -> 审计历史列表；change 项含 before/after 快照

# 擦除（request_id 幂等：同一标识重试只生效一次、只记一条审计）
lib.erase("w-001", request_id="req-erase-0001")
# 之后：get_profile -> None；历史中的 name/ssn -> None，company/state 仍可读；
# 该 workerID 永久禁止再登记；只要曾登记过（即使恢复后档案已不存在）仍可擦除。

# 备份 / 恢复
name = lib.backup()                  # -> 备份文件名，存于 <workdir>/backups/
lib.list_backups()                   # -> 全部备份文件名
lib.restore(name, request_id="req-restore-0001")
# 恢复语义：业务状态 = 备份状态 剔除全部已生效擦除对象；
# 审计账本与擦除事实不回滚（恢复前的审计项保留，备份中缺失的审计项并集合并）；
# 同一 request_id 的恢复请求重复提交是 no-op，不会覆盖其后发生的新变更。

lib.close()
```

## 保证与约束

- 备份文件只含 `profiles` / `audit` / `requests` 三张表，不含密钥与擦除台账。
- 恢复旧备份不会让已擦除的 PII 重新出现（密钥已销毁 + 恢复时按擦除台账过滤）。
- 请求真实性由上层核实，本库不鉴权。

## 运行测试

```bash
python3 -m unittest discover -s tests -v
```
