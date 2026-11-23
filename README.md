<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/card-zh-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/card-zh-light.png">
  <img alt="同步" src="assets/card-zh-light.png">
</picture>

- **三通道同步**：支持本地目录镜像、WebDAV 与 Git 仓库，配置后可同时启用并各自展示独立同步进度，可同时管多个笔记本。
- **保存即同步**：写完自动增量同步，也支持随时点「立即同步」。
- **定时同步**：开启自动同步后，每 5 分钟、30 分钟或 1 小时同步一次，默认 5 分钟。没有变更时不记录日志。连续失败只提醒一次。
- **冲突有兜底**：冲突副本 / 优先本地 / 优先远端任选，危险变更二次确认。开启缺失保护后，重新上传远端已删除的笔记须先确认。
- **删除会同步**：在任一端删除且另一端没改过的笔记和附件，下次同步时另一端也会删除，不会再被拉回来。本地删除进系统回收站，Git 留在提交历史，WebDAV 移到 `.block-sync-trash`，目录镜像移到恢复区，都能找回。一次删很多时会先请你确认。
- **异常提醒**：同步失败、发生冲突或需要确认时提醒。Block 在前台时显示窗口内提示，在后台时使用系统通知。投递失败后会在后续系统事件中重试。可在同步设置里关闭。
- **唤醒后补同步**：开启自动同步后，设备唤醒或网络恢复时按原有安全规则补同步。
- **Git 推送范围**：同步只自动推送可识别的 Block Sync 提交。分支中如有自己的未推送提交，请先在 Git 中检查并处理，再重试同步。
- **本地 Git 工作区**：先切换到同步设置中的分支。远端有新提交时，先在 Git 客户端更新工作区，再继续同步笔记。
- **系统凭据**：Git 令牌和 WebDAV 密码保存在系统凭据库。旧凭据在系统存储确认成功后迁移，凭据库锁定时会稍后重试。超出 1536 字节或含空字符的旧凭据会提示重新录入或清除。更改服务器、WebDAV 用户名或 Git 仓库时，请重新输入所需凭据。「清除凭据」适用于当前同步目标及账号的设置。Linux 使用 Secret Service。

**安装**：打开 Block「设置 → 应用商店」搜索 **同步**。支持插件系统权限的 Block 也可手动填入 `blockmd-plugins/block-sync`。

旧版 Block 可从应用商店安装兼容版本，也可手动安装 [v1.3.44 归档](https://github.com/blockmd-plugins/block-sync/releases/download/v1.3.44/block-sync-v1.3.44.tar.gz)。使用通知、系统凭据和唤醒补同步前请升级 Block。
