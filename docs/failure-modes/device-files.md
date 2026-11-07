# Failure modes: device file writes (app side)

`failure -> detection -> recovery` for writes through `/admin/devices/{id}/config/write`: the config editor, snapshot restore and the rules push (`pkg/web/admin_config.go::stagedWrite`). The firmware commands are in [`thesada-fw/docs/failure-modes/mqtt.md`](https://github.com/Thesada/thesada-fw/blob/main/docs/failure-modes/mqtt.md). A blank recovery cell is a gap.

One write per device runs at a time. It goes to `<path>.new` as `fs.write` plus `fs.append` chunks. The app sends `fs.mv <path>.new <path>` only after every chunk ack named the staged path with its full byte count and `fs.cat` reports a committed size equal to the content length. The live file is then either the old one or the new one, never a prefix of either.

| Failure | Detection | Recovery |
|---------|-----------|----------|
| A chunk fails, times out, or the session drops mid-sequence | Request ends `error` or `timeout`, the editor shows `chunk i/n ...` | **Automatic:** `fs.rm <path>.new`, the live file is untouched. Save again |
| A chunk ack with the wrong byte count or for another file | `chunk i/n short write: device replied ...` | **Automatic:** same cleanup |
| LittleFS full: the firmware acks `f.write` before `f.close`, whose failure it drops | `size check of <path>.new: device holds N bytes, want M` | **Automatic:** same cleanup. The staged write needs room for both copies, check `fs.df` |
| Rename refused (`Failed to rename`, the file is open elsewhere, firmware without `fs.mv`) | `rename <path>.new to <path> failed: ...` or `... device error: ...` | **Automatic:** same cleanup, the live file is untouched. Retry |
| A second write to the same device while one runs (double click, a second tab, restore or rules push) | HTTP 409 `a write to this device is already running`, nothing is sent | Wait for the first write to finish. The config page also disables Save while its write runs |
| A step waits out its deadline behind other CLI traffic to the device | `... timed out after ...`, and the command is never sent | **Automatic:** same cleanup. Retry when the device is idle |
| Cleanup `fs.rm` fails too | The message ends `(<path>.new may remain on the device, the next save overwrites it)` | Harmless leftover. The next save truncates it, or run `fs.rm <path>.new` |
| The rename answer is lost after the device applied it | `rename ... timed out` while the device already holds the new file | Read the file back with the editor before saving again |
| Path with whitespace, `*` or `?` | `path must not contain whitespace, * or ?`, nothing is sent | None. The device shell splits and globs those characters in `fs.mv` and `fs.rm` |
| Path on `/sd` | `files on /sd cannot be replaced atomically, the FAT rename refuses an existing file`, nothing is sent | None from the editor. FAT rename does not replace a file, so no atomic path exists. A plain `fs.write` from the MQTT shell page writes it in place, without that guarantee |
| Path within 4 bytes of the 64-byte device path cap | First chunk `device error: [Path too long]`, nothing written | Use a shorter path. The `.new` suffix takes 4 bytes |

## Gaps

- **The one-write guard is per app process.** Two app instances could still run overlapping writes to one device.
- **Other CLI traffic is not part of the guard.** A hand-typed `fs.*` command, from the config page CLI box or the MQTT shell page, to the same file can still race a save.
- **The device does not refuse an in-place write.** Another client with an mTLS session can still `fs.write /config.json` directly and truncate it. A firmware guard is a separate change.
- **A stale ack for the same staged path with the same byte count looks like a real one.** The raw `fs.write` path carries no req_id. The size check still catches it unless the sizes also match.
- **The success checks read reply text.** `fs.mv` and `fs.rm` print their failures with `ok:true`, the byte count and path come from the `Wrote N bytes to` line, and the size from the chunked `fs.cat` reply. A firmware reply rewording fails the write closed, it never installs an unverified file.
- **The firmware drops the `f.close` result on `fs.write`.** The app size check covers it. A firmware fix is separate.

---

Related: [`../invariants.md`](../invariants.md), [`../operator-role.md`](../operator-role.md), [`../runbook.md`](../runbook.md).
