"""库异常定义（骨架）。"""


class PrivacyErasureError(Exception):
    """库基础异常。"""


class WorkerExistsError(PrivacyErasureError):
    """workerID 已存在（或已被擦除，永久禁止再登记）。"""


class WorkerNotFoundError(PrivacyErasureError):
    """worker 从未登记。"""


class BackupNotFoundError(PrivacyErasureError):
    """备份文件不存在或不在受管备份目录内。"""
