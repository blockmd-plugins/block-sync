<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/card-en-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/card-en-light.png">
  <img alt="Sync" src="assets/card-en-light.png">
</picture>

Want your notes synced across devices like Obsidian Sync, Dropbox, or Nextcloud without paying for an extra official subscription? Sync automatically keeps your notebooks up to date across your own cloud folder (such as iCloud, Dropbox, or OneDrive), a WebDAV drive (such as Nextcloud), or a GitHub/Git repository so your data stays under your control.

- **Three ways to sync, multiple notebooks at once**: Connect local cloud folders, WebDAV drives, and Git repositories side by side, each showing its own progress across all your notebooks.
- **Syncs on save, on schedule, and after wake**: Notes sync incrementally as soon as you save, or whenever you click Sync Now. Automatic sync also checks every 10 minutes, 30 minutes, or 1 hour and catches up automatically after your computer wakes or reconnects.
- **Conflict copies and recoverable deletions**: Choose conflict copy, local-first, or remote-first when edits collide. Deletions sync across devices without losing data: local files go to your system Trash, WebDAV and mirrors move them to a recovery folder, Git keeps full commit history, and large batch deletions ask for confirmation first.
- **Clear alerts and keychain protection**: Get an in-app prompt or system notification when a sync fails, hits a conflict, or needs confirmation, while WebDAV passwords and Git tokens stay safely stored in your system keychain. (If you also commit to the same Git repo from another client, pull or merge your branch changes before syncing.)

**Install**: Open Block Settings -> App Store and search **Sync**, or enter `blockmd-plugins/block-sync`.

Older Block versions can install the compatible release from the App Store or use the [v1.3.44 archive](https://github.com/blockmd-plugins/block-sync/releases/download/v1.3.44/block-sync-v1.3.44.tar.gz). Upgrade Block to enable system notifications, keychain storage, and wake-up catch-up sync.
