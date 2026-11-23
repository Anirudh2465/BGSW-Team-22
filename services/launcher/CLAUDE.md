# Scoped Rules for Launcher Service (Owner: Dev 1)

Scope:
- Only edit files inside `services/launcher/`.
- Never expose `/var/run/docker.sock` to any other container or network.
- Ensure `launcher` network is isolated from `core`. Only `orchestrator` can talk to launcher.
- Stage 3 (`scan`) MUST run with `--network=none` without exception.
- Stage 1, 2, and 4 must strictly enforce resource caps and proxy routing.
- Test command: `pytest services/launcher/tests -v`
