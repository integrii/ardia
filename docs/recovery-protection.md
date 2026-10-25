# Recovery phrase protection

Viewing recovery words, QR codes, previews, or exporting a recovery kit requires Touch ID or the Mac password. Native authorization is bound to the current key generation and expires after 60 seconds. Closing the sheet or a browser window, locking the Mac, sleeping, replacing the key, and module teardown revoke access. Pending authentication and UI results cannot restore a revoked view.

Clipboard writes are current-host-only, marked concealed and transient, and cleared after at most one minute only if no newer clipboard write replaced them. Clipboard managers may ignore these advisory markers. Bytes already read by another process cannot be recalled.

Copied and shared PDFs use unique temporary directories with mode 0700 and files with mode 0600. Cleanup does not follow directory symlinks. Exports expire within five minutes, with earlier cleanup on clipboard expiry or share completion/cancellation. Startup cleans expired managed exports and the exact legacy kit filenames. A crash can leave files until the next startup; deletion is not secure erasure. The five-minute cap can interrupt a slow sharing service. Explicit saves and copies made by recipients are permanent and are not deleted by Ardia.

The phrase and rendered images still enter the app’s JavaScript memory after authorization. This is not protection against compromised app code, same-user malware, screenshots, or memory inspection. Password sync, the original password reader, generic payload handling, and key storage are unchanged. This narrowly scoped change does not resolve all of issue #241.

## Verification

```sh
bash packages/sync/scripts/recovery-protection.sh /path/to/scratch
```

The standalone checks compile the production helpers with injected authentication, private pasteboards and mock files, and execute the production UI hook under controlled hooks. They do not verify Expo integration, actual Touch ID/password prompts, delivered lock/sleep notifications, or rendered sheets. A full Xcode app build and isolated app verification are required before this draft is ready to merge.
