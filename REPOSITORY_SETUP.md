# Repository setup notes

## First push

From the local project root in PowerShell:

```powershell
git status
git remote -v
```

If Git has not been initialized:

```powershell
git init
git branch -M main
```

Set the GitHub remote (use `set-url` instead if `origin` already exists):

```powershell
git remote add origin https://github.com/038-Alav/WatchfulEye.git
```

Review ignored and untracked files before staging:

```powershell
git status --short
git check-ignore -v .venv .venv-build data\devices.json logs\watchfuleye.log build dist
```

Then stage and review the exact commit contents:

```powershell
git add .
git status --short
git diff --cached --stat
git diff --cached --name-only
```

Only after confirming that no local inventory, logs, secrets, virtual environments, or build output is staged:

```powershell
git commit -m "Initial public release: Watchful Eye 0.2.0"
git push -u origin main
```

If the GitHub repository was created with a README, license, or `.gitignore`, it already has a commit. In that case, fetch and inspect it before pushing; do not force-push:

```powershell
git fetch origin
git pull --rebase origin main
```

Resolve any merge/rebase conflict before continuing.

## Publish 0.2.0

After `main` has been pushed and the GitHub Actions workflow is visible, create and push the tag:

```powershell
git tag -a v0.2.0 -m "Watchful Eye 0.2.0"
git push origin v0.2.0
```

The workflow builds the Windows installer and publishes it as an asset on a GitHub Release. It also keeps a 30-day workflow artifact for troubleshooting. Check the Actions tab before sharing the release URL.

## Before making the repository public

- Confirm `data/*.json` and all files under `logs/` are ignored and not already tracked.
- Never commit real IP/MAC/hostname inventory exports or screenshots containing network identifiers.
- Do not commit `.venv`, `.venv-build`, `build`, `dist`, or installer executables.
- Choose and add a license deliberately. A public repository without a license is viewable, but others do not receive general permission to reuse its code.
