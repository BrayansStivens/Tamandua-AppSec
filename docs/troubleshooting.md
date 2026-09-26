English · [Español](es/solucion-problemas.md)

# Troubleshooting

Always start here:

```bash
make doctor     # requirements, permissions, port and engines
make status     # containers and engine images
make logs
```

The app's logs contain no passwords, tokens or keys, so you can share them when asking for help. Still, read them first in case they include repository names or domains you'd rather keep private.

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `opengrep` shows as *Exited* | That's expected: it only builds the engine image and checks that it starts. | Nothing to do. |
| The build fails at `sha256sum -c` | The downloaded Opengrep binary doesn't match the pinned hash. | Stop there: try again later and, if it keeps happening, open an issue. Never remove the check. |
| The panel doesn't open at `127.0.0.1:8766` | Another service is using the port, or the container didn't start. | Change `TAMANDUA_HOST_PORT`, along with `TAMANDUA_PUBLIC_URL` and `TAMANDUA_ALLOWED_ORIGINS`, in `.env`. |
| *Host not allowed* (403) | You're opening the panel with a URL that isn't in `TAMANDUA_ALLOWED_ORIGINS`. | Add it in `.env` and restart. |
| The container stops with *serves the panel over plain HTTP* | `TAMANDUA_PUBLIC_URL` points outside this machine without HTTPS. | Put HTTPS in front (see the README) or go back to `http://127.0.0.1:8766`. |
| I can't find the setup code | It was printed in the logs on first start. | `make setup-code`. If a user already exists, there's no code: sign in with that user. |
| `Permission denied` on `data/` or `config/` | Docker created the folders as root. | `sudo chown -R $(id -u):$(id -g) data config`; if your `.env` has a different UID/GID, delete it and run `make setup`. |
| A secret can't be decrypted | `TAMANDUA_MASTER_KEY` changed or `config/master.key` was lost. | Restore the key; if that's not possible, use *Forget the App* and reconnect GitHub, AI and Jira. |
| An engine shows as *Not tested* | Docker isn't reachable from the container, or the image is missing. | `make status` tells you which image is missing: `make build` for Opengrep and `make engines` for Trivy and Gitleaks. |
| The CVE tracker is slow at first | The local NVD copy is still downloading (progress is shown at the top). | Wait, or add `TAMANDUA_NVD_API_KEY`. |
| Linux: scans with suspiciously few findings, or new `trivy-cache-<uid>` caches | Before 23 Sep 2026 the engines ran as root with no capabilities, which on Linux can't read the app's private folders and silently returned zero findings. They now run with the app's UID; if root created an old cache, a new one is used next to it. | Rerun any scans done on Linux before you upgraded. The old caches (`data/trivy-cache`, `data/grype-cache`) can be removed with `sudo rm -rf` once the suffixed version exists. |
| A scan is *Failed* after a restart | On startup, any scan left halfway is marked as failed. | Launch it again. |
| I lost my two-factor device | — | Another admin removes it under **Users**, or from the CLI: `make cli ARGS="user reset-totp --username your-user"`. |
| I forgot my password | — | **Users → Send password link**, or `user reset-password` from the CLI. |
| The panel, a report or a PR comment is in the wrong language | The panel follows the browser; everything else uses `TAMANDUA_DEFAULT_LOCALE`. | Use the language switch in the sidebar (or on the sign-in screen); for reports, PR comments, notifications, Jira and the CLI, set `TAMANDUA_DEFAULT_LOCALE=en` or `es` in `.env` and run `docker compose up -d`. |
