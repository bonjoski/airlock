# Recipe: Archive Extraction & Zip-Slip Path Confinement

> **Use Case ID:** `AIR-UC-07`  
> **Mitigated Advisory:** `GHSA-qh76-45cr-8xrc` (`CVE-2026-61725`, `sevenz-rust2` Zip-Slip)  
> **Isolation Mechanism:** Fail-Closed Pre-Flight Archive Confinement Gate (`ValidateArchiveEntryPath` & `ValidateArchiveCommandConfinement`)  

---

## 1. Problem Statement

Archive extraction libraries and utilities (such as `sevenz-rust2 < 0.21.1`, `7z`/`7zz`, `tar`, `unzip`, `bsdtar`) can suffer from **Zip-Slip** path traversal (`dest.join(entry.name())` without canonical boundary verification), allowing a crafted archive or extraction invocation to write files outside the intended workspace root (e.g., `~/.ssh/authorized_keys`, `~/.zshrc`, or sibling repositories).

## 2. How Airlock Enforces Archive Confinement

Airlock enforces fail-closed archive confinement across macOS (Seatbelt), Linux (Bubblewrap/Landlock), and Windows (Job Objects):

1. **Command-Level Pre-Flight Gate (`ValidateArchiveCommandConfinement`):**
   - Intercepts archive utilities (`7z`, `7za`, `7zz`, `sevenz`, `tar`, `bsdtar`, `unzip`, `unrar`, `cpio`, even behind `env`/path wrappers).
   - Blocks unsafe extraction flags (`-P`, `--absolute-names`, `--keep-directory-symlink`, `-spe`, `-snl`, `-snh`).
   - Resolves extraction targets (`-o<dir>`, `-C <dir>`, `--directory=<dir>`, `-d <dir>`) through canonical symlinks and rejects any destination outside `WorkspaceRoot`.
2. **Entry-Level Zip-Slip Validator (`ValidateArchiveEntryPath`):**
   - Rejects NUL bytes, Windows drive letters, UNC/absolute paths, POSIX/Windows `..` segments, URL-encoded `%2e%2e` traversals, and symlink-hop escapes before file creation.

## 3. Verification Example

```bash
# Benign extraction confined inside the workspace succeeds:
airlock run -- tar -xzf release.tar.gz -C ./build/out

# Out-of-workspace extraction or unsafe flags fail closed immediately:
airlock run -- 7zz x payload.7z -o../../outside
# -> sandbox: archive path escape blocked (Zip-Slip confinement)
```
