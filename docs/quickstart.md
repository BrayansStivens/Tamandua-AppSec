English · [Español](es/inicio-rapido.md)

# Quickstart

From zero to a verified fix in about 15 minutes. Steps marked **optional** can wait.

## 1. Start it (5 min)

You need Docker (Engine 24+ with Compose v2.24+), `make` and `git`. `make doctor` checks that everything is in
place.

```bash
git clone https://github.com/BrayansStivens/Tamandua-AppSec.git
cd Tamandua-AppSec
make up
```

The first run pulls the engines (a few minutes). When it's done it prints the URL (<http://127.0.0.1:8766>) and a
single-use **setup code**: you use it to create the admin account in the panel. If you lose it, `make setup-code`
prints it again.

Then, under **Account**, turn on two-factor authentication.

The panel follows your browser's language; switch it any time from the sidebar or the sign-in screen. PR comments,
notifications, Jira, reports and CLI output use `TAMANDUA_DEFAULT_LOCALE` (`en` by default, see
[configuration.md](configuration.md)).

## 2. See it work without connecting anything (2 min)

```bash
make demo
```

It runs a real scan, with the same engines as the panel, over the intentionally vulnerable examples shipped with
the repository (code in seven languages, dependencies with CVEs, a secret and a Dockerfile) and imports a sample
threat model. In the panel you'll see the **demo** asset:

- **Overview:** findings by severity, active exploitation (KEV) and what to handle first.
- **Findings:** expand one and look at **How to fix it** (the command or the code example). **Verify again** works on your own repositories.
- **Threats:** the diagram, the threats and the PDF report.

`make demo IMAGE=nginx:1.21` also scans a public image (Trivy + Grype, a couple of minutes).

## 3. Connect your GitHub repositories (5 min)

Under **Integrations → Code providers**, the panel walks you through creating your server's GitHub App with only
the permissions it needs (read code, comment and set statuses on PRs). At the end you install it on the
repositories you want: *Only select repositories* is the best way to start. Details in [github-app.md](github-app.md).

Not on GitHub (GitLab, Bitbucket, Azure DevOps or a local folder)? Use [`scan` in the terminal or in CI](cli.md).

## 4. First scan and first fix

1. **New scan → Code scan**, pick one or more repositories (or a whole organization) and launch it.
2. In **Findings**, start with anything marked KEV or critical. Every finding includes **How to fix it**.
3. Apply the fix, push it to the main branch and click **Verify again**: when the scan finishes it tells you
   "Fixed ✓" or "Still present".

If you decide not to fix something, record it in triage (accepted risk or false positive) with a reason and an
expiry date: it stays as evidence and stops getting in your way.

## 5. Let it run on its own (optional, recommended)

- **Pull requests and main branch:** in **Pull requests**, an admin turns on watching for your repositories. Every
  PR is reviewed automatically (only what it introduces counts) and the main branch is rescanned after each merge.
- **Daily new-advisory check:** on by default. Once a day your dependencies are checked, offline, against the
  advisories published since the last scan.
- **Alerts in your channel:** under **Integrations → Alerts**, add Slack, Teams or a webhook so you hear about
  things without opening the panel. For messages to link to the finding, set `TAMANDUA_PUBLIC_URL`.

## 6. Later on (optional)

- **Team:** invite more people under **Users** (member or admin role).
- **Jira:** under **Integrations**, to turn findings into issues without duplicates.
- **Private images:** read-only credentials under **Integrations → Container registries**.
- **Audits:** in Findings, **More formats → Audit evidence (SOC 2, ISO…)** generates the PDF (or **Report on selected** for the ones you check).
- **From another machine:** put it behind HTTPS (see the README); outside `127.0.0.1` it won't start without HTTPS.

Something not working? See [troubleshooting.md](troubleshooting.md) or run `make doctor`.
