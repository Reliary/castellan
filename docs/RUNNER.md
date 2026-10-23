# The battery runner

`.github/workflows/battery.yml` runs the wired-system suites on a machine that
has a real user session, a user cgroup slice and a pty — none of which a
GitHub-hosted runner has. That machine is a single box, registered repo-scoped
as `cachyos-ci`.

This document exists because the setup was undocumented: rebuilding the runner
from scratch was an unrecorded procedure. If the box dies, this is the list.

## Requirements on the box

- Linux 7.x with Landlock ABI ≥ 4 (the suites assert real kernel behaviour).
- cgroup v2 unified hierarchy.
- A user systemd manager for the runner uid, with `Linger=yes`. Without linger
  the jobs cannot run `systemctl --user`, and `p18`, `p20` and `p21-desktop`
  fail with "no user systemd manager".
- Rust stable, gcc, make, python3, git, pkg-config, and util-linux `script`.
- `sudo` is not required by the suites. The runner user must not be in
  `docker`, `libvirt`, `wheel` or `systemd-journal`: those groups would make the
  uid boundary decorative for the jobs that run there.

## Why a dedicated uid

The suites are destructive by design: they kill daemons, freeze every session
scope in the user's slice, install and uninstall real systemd user units, and
`p18` runs `castellan uninstall --yes` against the real state dir. Running the
battery as the interactive account would freeze that human's live agent
sessions. A separate `ci` user gets its own `user@<uid>.service` and therefore
its own cgroup tree, session scope and state.

## Rebuild

```sh
# 1. dedicated user, never the interactive account
useradd -m -s /bin/bash ci
loginctl enable-linger ci
loginctl show-user ci -p Linger        # expect Linger=yes

# 2. runner binary at the version currently registered
su - ci
gh release download --repo actions/runner -p 'actions-runner-linux-x64-<ver>.tar.gz'
mkdir -p ~/actions-runner
tar xzf actions-runner-linux-x64-*.tar.gz -C ~/actions-runner
sudo ~/actions-runner/bin/installdependencies.sh

# 3. register. NAME and LABELS must match battery.yml, or every job queues
#    forever with no error. --replace removes the stale offline entry; without
#    it you end up with two registrations and jobs still match the dead one.
TOKEN=$(gh api -X POST repos/Reliary/castellan/actions/runners/registration-token --jq .token)
~/actions-runner/config.sh --url https://github.com/Reliary/castellan \
  --token "$TOKEN" --name cachyos-ci --labels battery --unattended --replace

# 4. service (from ~ci/actions-runner, as root)
sudo ./svc.sh install ci
sudo ./svc.sh start
sudo systemctl enable actions.runner.Reliary-castellan.cachyos-ci.service

# 5. prove it
gh api repos/Reliary/castellan/actions/runners --jq '.runners[]|[.name,.status]|@tsv'
gh workflow run battery.yml --ref quattro
```

## Operating it

- **Health**: `battery-watch.yml` runs every six hours and fails if the runner
  is not `online` or the newest `quattro` commit has no green battery run.
- **A red battery**: read `gh run view <id> --log-failed`. The per-suite table
  and the first failing assertions are on stdout, so the run log is usually
  enough. The full logs stay on the runner under the path printed as `logs:`.
- **Suspect leftover state** (several suites failing with "daemon not
  responding" at once): the previous run left a unit or a socket behind. Run
  the cleanup the workflow runs on every exit:

  ```sh
  sudo -u ci XDG_RUNTIME_DIR=/run/user/$(id -u ci) systemctl --user \
    disable --now castellan.service
  sudo -u ci rm -f ~ci/.config/systemd/user/castellan*.service
  sudo -u ci XDG_RUNTIME_DIR=/run/user/$(id -u ci) systemctl --user daemon-reload
  sudo -u ci XDG_RUNTIME_DIR=/run/user/$(id -u ci) systemctl --user reset-failed
  sudo -u ci rm -rf ~ci/.local/state/castellan ~ci/.config/castellan
  ```

- **Scratch retention**: every run creates a `castellan-run-all.*` log dir
  (removed on success, kept on failure) plus suite work dirs. Prune them:

  ```sh
  find /tmp -maxdepth 1 -name 'castellan-*' -mmin +1440 -exec rm -rf {} +
  find /tmp -maxdepth 1 -name 'cast-p*' -mmin +1440 -exec rm -rf {} +
  ```

  A daily systemd timer running those two lines is enough; a battery run takes
  minutes, so a 24-hour age threshold can never delete a live run.

- **Workspace growth**: `du -sh ~ci/actions-runner/_work ~ci/.cargo`. GitHub
  keeps the last few checkouts; delete `_work` between jobs only if disk is
  tight (it costs a fresh clone each run).

## Trust boundary

Merging to `quattro` means running the merged tree's `build.rs` and shell on
this box as `ci`. The workflow is push-only and never `pull_request`, so a fork
PR cannot execute here directly; but a merged contributor change does, and so
does a `workflow_dispatch` from anyone with write access (which runs that ref's
workflow file). Treat merge rights as code-execution rights on the runner.

The job token is read-only (`contents: read`) and no OIDC token is requested.
`actions/checkout` persists that token in `.git/config` for the job's lifetime.

## Known limitations

- One runner: while it is offline, pushes queue and nothing fails. The watchdog
  is what breaks that silence.
- The box is not ephemeral. A malicious merged change could install a user unit
  that survives the job; the `always()` cleanup removes the units the battery
  itself creates, not arbitrary ones.
- `aarch64` is build-verified only; the battery runs on x86_64.
