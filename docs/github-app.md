English · [Español](es/github-app.md)

# Connecting GitHub

Every Tamandua installation uses **its own** GitHub App: you create it, on your account or on an organization you administer. If you need several organizations, set it up so it can be installed on any account. GitHub doesn't let you create Apps through the API, so this happens in GitHub's form. The panel (**Integrations**) shows this same guide with the values already filled in for your installation, plus buttons to copy them.

## 1. Create the App

Open the new App form:

- Personal account: <https://github.com/settings/apps/new>
- Organization: `https://github.com/organizations/<your-org>/settings/apps/new`

Fill in only these fields:

| Field | Value |
| --- | --- |
| **GitHub App name** | Anything you like, e.g. `Tamandua`. It must be unique across GitHub: if it's taken, add your team's name. |
| **Homepage URL** | Any URL of yours, e.g. your GitHub profile or your panel's URL. |
| **Callback URL** | Leave empty. |
| **Request user authorization (OAuth) during installation** | Unchecked. |
| **Setup URL** (optional) | `http://127.0.0.1:8766/oauth/callback` (or your public URL + `/oauth/callback`), and check **Redirect on update**. It opens a page that tells you how to pick the installation in the panel. |
| **Webhook → Active** | Unchecked. The panel polls pull requests on its own. |

**Repository permissions**, only these four:

| Permission | Access | Why |
| --- | --- | --- |
| Contents | Read-only | Download the code to scan it. |
| Metadata | Read-only | Required for every App. |
| Pull requests | Read and write | Read the PR's changes and leave a comment with the result. |
| Commit statuses | Read and write | Mark the commit as passing or blocked. |

Nothing under *Organization permissions* or *Account permissions*, and no subscribed events. If the App ever ends up with more permissions than it needs, the panel flags it in red.

Under **Where can this GitHub App be installed?**, choose **Any account** if you need to install it on several organizations. For a single account, **Only on this account** is enough. Then click **Create GitHub App**.

## 2. App ID and private key

On the page of the App you just created:

- **App ID**: shown at the top, in the *About* section.
- **Private keys → Generate a private key**: downloads a `.pem` file.

## 3. Connect it to the panel

In **Integrations → GitHub**, enter the App ID, pick the `.pem` file and click **Verify and save**. The panel signs a JWT with the key and asks GitHub about the App: if they don't match, nothing is saved and the panel tells you why. If they match, it stores the key **encrypted** in `config/` and shows the name, the account and the permissions GitHub reports for the App.

The key never leaves the server again. **Delete the `.pem` from your downloads folder** when you're done.

## 4. Install it on your repositories

Click **Install on GitHub**, choose an account and **Only select repositories**, and tick the repositories you want to scan. Repeat the installation for each organization. Back in the panel, click **Find installations** and then **Connect account** for each organization you want to use: installing the App doesn't add those accounts to this workspace by itself. Repositories from connected accounts appear in **Repositories** and **New scan**, where you can filter by organization.

To add or remove repositories later: **Integrations → Change repositories** on the relevant account. To stop using an organization here, click **Disconnect account**.

## Pull request review

In **Pull requests**, turn on watching per repository and choose the blocking threshold. Every few minutes (`TAMANDUA_PR_POLL_SECONDS`), open PRs with new commits are reviewed: only what the PR introduces compared with the main branch counts. The result is published as **a single comment** that gets updated, and as a `tamandua` commit status. The comment speaks the language set in `TAMANDUA_DEFAULT_LOCALE` (English by default, or Spanish), because the whole team reads it.

## Alternative: mount the App as a secret

If you'd rather not keep the key in the vault (for example, because you already use a secrets manager), set these in the container's environment:

```bash
GITHUB_APP_ID=123456
GITHUB_APP_SLUG=your-app        # the one in github.com/apps/<slug>
GITHUB_APP_PRIVATE_KEY_FILE=/run/secrets/github-app.pem
```

The environment takes precedence over the vault. Mount the `.pem` read-only.

## Switching Apps

**Integrations → Use a different GitHub App… → Forget the App** deletes the key and the connection from the server. The App still exists on GitHub: delete it there if you no longer use it.

## Common problems

| Message | What's going on |
| --- | --- |
| *GitHub doesn't recognize that App ID with that private key* | The key belongs to another App, or you revoked it. Generate a new one on the App's page. |
| *The private key must be RSA with at least 2048 bits* | You uploaded a different file; use the `.pem` GitHub downloads. |
| *The App isn't installed on any account yet* | Step 4 is missing, or you cancelled it on GitHub. |
| *Missing permissions* | You changed the App's permissions and the installation hasn't accepted the update: accept it on GitHub (*Settings → Applications → Installed GitHub Apps*). |
| GitHub rejects the Setup URL | Leave it empty and use **Find installations**; it works just the same. |
