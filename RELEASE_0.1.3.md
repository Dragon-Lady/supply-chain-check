# v0.1.3 (Unreleased)

Not yet released. No release date is set.

## Behavior changes

- **An unlistable directory makes the scan incomplete and exits 3.** A
  directory that exists but cannot be listed (for example permission denied)
  is still reported as a low `read-error` finding, as before; the overall
  risk level is unchanged. In addition the JSON report now has a `coverage`
  block (`complete: false`, `unlistableDirectories`), the text output prints a
  `Coverage: INCOMPLETE` line, and the CLI exits 3 unless a higher code
  applies. Previously such a scan exited 0.
- Exit codes are now documented in full: 0 clean and complete, 1
  scanner/runtime error, 2 likely exposure, 3 scan incomplete (unlistable
  directory or incomplete Tensorlake candidate inspection), 4 token-monitor
  artifact (follow the STOP guidance). Precedence: 4 > 2 > 3 > 0.
- Build-output folders (`dist`, `build`, `coverage`, `.next`) inside
  installed dependencies are now scanned. Projects with large dependency
  trees may take a little longer and may see new findings there.

## Fixes

- Build-output folders were skipped at any depth, including inside
  `node_modules`, where compromised packages often ship their payload. They
  are now skipped only in the project itself.
- Scanning an installed package directly (`node_modules/<pkg>`, or a symlink
  to one) now also walks its `dist/` and `build/` folders.
- A directory that could not be listed used to be skipped silently. It is
  now reported and marks the scan incomplete.
