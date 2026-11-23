<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/card-en-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/card-en-light.png">
  <img alt="Sync" src="assets/card-en-light.png">
</picture>

- **Three backends**: Sync multiple notebooks over Local Mirror, WebDAV, and Git; configured targets run simultaneously with independent progress bars.
- **Auto on save**: Incremental sync runs automatically on save, plus one-click Sync Now.
- **Scheduled sync** — With automatic sync enabled, sync runs every 5 minutes, 30 minutes, or 1 hour (default: 5 minutes). Runs with no changes add no log entry. Repeated failures alert only once.
- **Conflict-safe**: Choose conflict copy, local-first, or remote-first with destructive guardrails. With deletion protection enabled, confirm before uploading a note that was deleted remotely.
- **Deletions sync**: A note or attachment deleted on one side and unchanged on the other is deleted there on the next sync instead of coming back. Local files go to the system Trash, Git keeps them in history, WebDAV moves them to `.block-sync-trash`, and mirrors move them to the recovery folder. Large batches ask for confirmation first.
- **Sync alerts** — Get an alert when sync fails, encounters a conflict, or needs approval. Block uses an in-app alert in the foreground and a system notification in the background. If delivery fails, Sync retries on a later system event. You can turn alerts off in sync settings.
- **Resume sync** — With automatic sync enabled, sync runs after the computer wakes or reconnects, using the existing safety checks.
- **Git pushes** — Sync pushes commits it can identify as its own. Review and handle any other unpushed commits in Git before retrying sync.
- **Local Git worktrees** — Switch to the configured branch before syncing. If the remote branch has new commits, update the worktree in your Git client before resuming notebook sync.
- **System credentials** — Git tokens and WebDAV passwords go in the system credential store. Existing credentials migrate after a verified write. Migration retries if the store is locked. Replace or clear old credentials that exceed 1536 bytes or contain NUL characters. Re-enter credentials when changing the server, WebDAV username, or Git repository. Clear Credential applies to settings for the current destination and account. Linux uses Secret Service.

**Install**: Open Block Settings → App Store and search **Sync**. If your version of Block supports system permissions for plugins, you can also enter `blockmd-plugins/block-sync`.

Older Block versions can install the compatible version from the App Store or use the [v1.3.44 archive](https://github.com/blockmd-plugins/block-sync/releases/download/v1.3.44/block-sync-v1.3.44.tar.gz). Upgrade Block to use notifications, system credentials, and resume sync.
