# privacy-erasure：员工档案隐私擦除库

供 EOR 运营上层系统直接调用的 Python 库。业务状态与审计账本保存在 SQLite，
备份为本地文件，密钥保存在独立目录（永不进入备份）。仅依赖 Python 标准库。

## 核心机制：crypto-shredding

- 姓名、SSN 为 PII，以**每 worker 独立随机密钥**加密后写入账本与备份；
  客户公司、州为非 PII，明文存储。
- 密钥保存在 `数据目录/keys/`，**不进入任何备份**。
- 擦除 = 销毁该 worker 的密钥。此后即使持有当前全部受管文件与全部历史
  备份，该 worker 的全部历史 PII（含审计中的前后值）在密码学上不可恢复；
  而审计中的 workerID、非 PII 内容与操作事实仍明文可读。
- 恢复旧备份只会还原业务状态（当前档案表），且自动剔除全部已生效擦除对象；
  审计账本、擦除登记、请求记录**永不回滚**，被擦除者的 PII 不会因恢复而重现。

## 数据目录布局

```
数据目录/
├── ledger.sqlite3   # 当前档案 + 追加式审计 + 擦除登记 + 请求去重
├── keys/            # 每 worker 的 PII 密钥（受管但不入备份）
└── backups/         # create_backup 生成的账本快照（仅含密文 PII）
```

## 快速开始

```python
from privacy_erasure import PrivacyErasureService

svc = PrivacyErasureService("/path/to/data-dir")

# 登记与更新（姓名/SSN 为 PII，公司/州为非 PII）
svc.register("w-001", "Alice", "111-11-1111", "ACME", "CA")
svc.update("w-001", name="Alicia", ssn="111-11-1112")

# 读取当前档案与历史变更（未擦除时 PII 完整可读）
svc.get_profile("w-001")     # -> dict 或 None
svc.get_history("w-001")     # -> 该 worker 的审计条目列表
svc.get_audit_log()          # -> 全量审计账本（含恢复等全局事件）

# 备份与恢复（恢复仅限本目录 backups/ 内的备份）
backup = svc.create_backup()
svc.restore("req-restore-001", backup)

# 擦除：覆盖全部历史姓名与 SSN；当前档案删除；workerID 永久禁止再登记
svc.erase("req-erase-001", "w-001")

svc.close()
```

## 语义说明

- **擦除生效后**：`get_profile` 返回 `None`；`get_history` 中该 worker 的
  PII 字段为 `None` 且 `readable=False`，workerID、公司、州、操作事实仍可读；
  同名 workerID 再 `register` 抛出 `WorkerExistsError`。
- **只要曾登记过即可擦除**：即使恢复旧备份后当前档案已不存在，仍可对其
  执行 `erase` 以抹除历史中残留的 PII。
- **幂等**：`erase` 与 `restore` 携带唯一 `request_id`。相同标识重试只产生
  一次业务效果和一条审计项；已完成的恢复请求再次提交不会覆盖其后发生的
  新变更。
- **恢复结果**：等于所选备份中的当前档案剔除全部已生效擦除对象后的状态；
  恢复前已有的审计项全部保留。

## 运行测试

```bash
python3 -m unittest discover -s tests -v
```

覆盖场景：多次更名/改 SSN 后擦除（历史 PII 不可恢复、非 PII 审计可读、
其他 worker 不受影响）；交替备份/修改/擦除/恢复的一致性核对；当前档案
已不存在但历史仍有 PII 的 worker 的擦除；重复恢复请求的幂等性。
