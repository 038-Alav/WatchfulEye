# Changelog

## 0.2.0 — Phase 4 usability and Windows packaging preparation

- Display persisted UTC timestamps in the machine's local timezone.
- Add row-based device selection and a device details dialog.
- Show the latest classifier rationale, candidate support scores, and full per-device observation history.
- Persist explainable `Unknown` classification outcomes, including why no conclusion was reached.
- Migrate legacy project-local JSON stores into the per-user data directory without overwriting existing user data.
- Store inventory, scan history, observations, and logs outside the installation directory.
- Log each discovery-provider completion once instead of repeating earlier provider results.
- Add PyInstaller onedir and Inno Setup build definitions, a Windows PowerShell build script, and a Windows CI workflow.
