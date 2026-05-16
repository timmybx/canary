# CANARY Deployment Notes

These notes capture the current Render deployment setup for CANARY, including the web service, custom domain, persistent data disk, SSH access, and data synchronization workflow.

## Current Hosting Setup

CANARY is deployed on Render as a Docker-based Web Service.

- **Render service name:** `canary`
- **Service ID:** `srv-d83pq1v7f7vs739dbv3g`
- **Repository:** `https://github.com/timmybx/canary`
- **Branch:** `main`
- **Dockerfile path:** `./Dockerfile`
- **Docker build context:** repository root, `.`
- **Public domain:** `https://canary-score.com`
- **WWW domain:** `https://www.canary-score.com`
- **Render fallback URL:** `https://canary-16i1.onrender.com`

Render is configured to auto-deploy from GitHub when changes are pushed to `main`.

## Auto-Deploy Workflow

Normal code update workflow:

```bash
git add .
git commit -m "Describe the CANARY change"
git push origin main
```

Render should automatically detect the push, rebuild the Docker image, and redeploy the service.

To intentionally avoid an automatic Render deploy for a commit, include a Render skip phrase in the commit message, such as:

```bash
git commit -m "Update notes [skip render]"
```

## Runtime Environment Variables

The Render web service should define these environment variables:

```text
CANARY_WEB_HOST=0.0.0.0
CANARY_DATA_DIR=/app/data
PYTHONUNBUFFERED=1
```

Do **not** hard-code the Render port. The web app should read Render's `PORT` environment variable and fall back to `CANARY_WEB_PORT` or `8000` for local use.

Expected web startup behavior:

```python
host = os.getenv("CANARY_WEB_HOST", "127.0.0.1")
port = int(os.getenv("PORT", os.getenv("CANARY_WEB_PORT", "8000")))
```

This keeps local direct runs safer by defaulting to `127.0.0.1`, while Render overrides the host to `0.0.0.0`.

## Docker Startup

The Docker image should start the CANARY web app, not the CLI help screen.

Expected Dockerfile command:

```dockerfile
CMD ["python", "-m", "canary.webapp"]
```

The container should run as a non-root user, but the user needs a real shell so Render SSH works:

```dockerfile
RUN addgroup --system appgroup \
 && adduser --system --ingroup appgroup --home /app --shell /bin/sh appuser \
 && mkdir -p /app/data \
 && chown -R appuser:appgroup /app
USER appuser
```

The image also needs `rsync` installed so data can be synchronized to the Render persistent disk:

```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends libatomic1 libgomp1 jq rsync \
 && rm -rf /var/lib/apt/lists/*
```

## Persistent Data Disk

CANARY uses a Render persistent disk mounted at:

```text
/app/data
```

The disk stores runtime data that is **not** committed to GitHub, including processed datasets, model artifacts, CSV/JSONL files, and scoring inputs.

Current disk size:

```text
10 GB
```

This replaced the original 1 GB disk because larger CANARY files, such as monthly feature JSONL files, exceeded the available space.

Check disk usage from Render SSH:

```bash
df -h /app/data
du -sh /app/data
```

List data folders:

```bash
find /app/data -maxdepth 2 -type d | sort | head -50
```

## SSH Access to Render

Use SSH to access the running Render service container. This is the doorway to the persistent disk mounted at `/app/data`.

From WSL/Ubuntu:

```bash
ssh -i ~/.ssh/id_ed25519 -o UpdateHostKeys=no \
  srv-d83pq1v7f7vs739dbv3g@ssh.oregon.render.com
```

The `UpdateHostKeys=no` flag avoids an OpenSSH host-key update warning seen with Render SSH.

If SSH says the account is not available, verify that the Dockerfile creates `appuser` with a real shell, such as `/bin/sh`.

## WSL SSH Key Setup

When using WSL/Ubuntu, do not point SSH directly at the Windows-mounted private key under `/mnt/c/...`, because OpenSSH may reject it as too permissive.

Copy the key into the WSL home directory and set strict permissions:

```bash
mkdir -p ~/.ssh
cp /mnt/c/Users/Timmy/.ssh/id_ed25519 ~/.ssh/id_ed25519
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519
```

Optional public key copy:

```bash
cp /mnt/c/Users/Timmy/.ssh/id_ed25519.pub ~/.ssh/id_ed25519.pub
chmod 644 ~/.ssh/id_ed25519.pub
```

## Installing rsync in WSL/Ubuntu

If `rsync` is not installed in Ubuntu/WSL:

```bash
sudo apt update
sudo apt install rsync
```

If `dpkg` was interrupted:

```bash
sudo dpkg --configure -a
sudo apt update
sudo apt install rsync
```

If there are broken dependencies:

```bash
sudo apt --fix-broken install
sudo apt install rsync
```

Verify installation:

```bash
rsync --version
```

## Syncing Local Data to Render

From WSL/Ubuntu, change to the CANARY repo:

```bash
cd /mnt/c/Users/Timmy/OneDrive/Documents/GitHub/canary
```

Sync the **contents** of local `data/` to Render's persistent `/app/data` disk:

```bash
rsync -avz --progress --partial --append-verify \
  -e "ssh -i ~/.ssh/id_ed25519 -o UpdateHostKeys=no -o ServerAliveInterval=30 -o ServerAliveCountMax=6" \
  data/ \
  srv-d83pq1v7f7vs739dbv3g@ssh.oregon.render.com:/app/data/
```

The trailing slash on `data/` is important. It means copy the contents of `data/` into `/app/data/`, instead of creating `/app/data/data/`.

Do **not** use `--delete` unless the local `data/` folder is definitely the source of truth and it is safe to remove files from Render that are not present locally.

## Syncing Selected Data Folders

For smaller or safer uploads, sync only selected folders.

Processed data:

```bash
rsync -avz --progress --partial --append-verify \
  -e "ssh -i ~/.ssh/id_ed25519 -o UpdateHostKeys=no -o ServerAliveInterval=30 -o ServerAliveCountMax=6" \
  data/processed/ \
  srv-d83pq1v7f7vs739dbv3g@ssh.oregon.render.com:/app/data/processed/
```

Raw data:

```bash
rsync -avz --progress --partial --append-verify \
  -e "ssh -i ~/.ssh/id_ed25519 -o UpdateHostKeys=no -o ServerAliveInterval=30 -o ServerAliveCountMax=6" \
  data/raw/ \
  srv-d83pq1v7f7vs739dbv3g@ssh.oregon.render.com:/app/data/raw/
```

Model artifacts:

```bash
rsync -avz --progress --partial --append-verify \
  -e "ssh -i ~/.ssh/id_ed25519 -o UpdateHostKeys=no -o ServerAliveInterval=30 -o ServerAliveCountMax=6" \
  data/processed/models/ \
  srv-d83pq1v7f7vs739dbv3g@ssh.oregon.render.com:/app/data/processed/models/
```

## Verifying Uploaded Data

SSH into Render:

```bash
ssh -i ~/.ssh/id_ed25519 -o UpdateHostKeys=no \
  srv-d83pq1v7f7vs739dbv3g@ssh.oregon.render.com
```

Then inspect the data disk:

```bash
ls -lah /app/data
find /app/data -maxdepth 2 -type d | sort | head -50
du -sh /app/data/*
df -h /app/data
```

## Public Demo Safety Notes

The public Render deployment should expose only the scoring/demo functionality.

Public UI should include:

- Plugin scoring
- ML/baseline result views
- Explanation/reason display
- Dataset/model metadata
- Research-prototype disclaimer

Public UI should **not** expose:

- Data collection controls
- Training controls
- Athena/GHArchive/SWH collection jobs
- Arbitrary command execution
- Admin/debug endpoints
- Secrets or tokens

Recommended disclaimer wording:

```text
CANARY is a research prototype for estimating near-term Jenkins plugin advisory risk.
Scores are decision-support signals and do not indicate that a plugin is safe or vulnerable.
```

## Useful Troubleshooting

If Render starts the CLI help screen instead of the website, check the Dockerfile `CMD`.

If Render logs say no open ports were detected, check:

```text
CANARY_WEB_HOST=0.0.0.0
```

and verify the app reads Render's `PORT` variable.

If SSH shows this warning:

```text
client_global_hostkeys_prove_confirm: server gave bad signature for ED25519 key
```

add:

```bash
-o UpdateHostKeys=no
```

If SSH says:

```text
This account is currently not available.
```

make sure the Dockerfile creates `appuser` with `--shell /bin/sh`.

If rsync says:

```text
remote command not found
```

install `rsync` in the Docker image.

If rsync fails around the same byte count with `Broken pipe`, check disk space:

```bash
df -h /app/data
```

A repeated failure near the same file size often means the persistent disk is full.

## Current Mental Model

Render deployment is structured like this:

```text
GitHub repo
  -> Render builds Docker image
  -> Docker image runs CANARY web app
  -> Render mounts persistent disk at /app/data
  -> CANARY reads runtime data from /app/data
  -> Data is updated with rsync over SSH
```

This mirrors the local development model where source code lives in Git, while large runtime data lives outside the repo.
