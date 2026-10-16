# ghostaction-history-sweeper

**A defensive mirror of the attacker's own playbook.** In October 2026, the GhostAction campaign (~1,900 compromised GitHub accounts, 30,000+ repos) added **git-history secret scanning** to its payload: attackers diff every commit in your history, betting you never rotated secrets that were committed — even ones deleted later.

This tool does exactly that scan, so you can find and rotate leaked secrets **before** an attacker does.

Built by [Ingenious AI](https://github.com/Iceman2050). Zero dependencies — Python stdlib only.

## The problem

Deleting a secret from your code doesn't delete it from git history. Every commit that ever contained an AWS key, a GitHub token, or an API key is still reachable — and modern attack tooling (like GhostAction's v2 payload) scans history automatically. The fix isn't just "remove it" — it's **find every historical occurrence and rotate**.

## Install

```bash
git clone https://github.com/Iceman2050/ghostaction-history-sweeper.git
cd ghostaction-history-sweeper
# nothing to install — stdlib only, Python 3.9+
```

## Usage

```bash
python3 src/history_sweeper.py --repo /path/to/your/repo --output rotation-checklist.md
python3 src/history_sweeper.py --repo /path/to/your/repo --since 2024-01-01
```

Flags:

| Flag | Description |
|------|-------------|
| `--repo` | Path to the git repository to scan (required) |
| `--output` | Write the markdown rotation checklist to this file |
| `--since` | Only scan commits after this date (e.g. `2025-01-01`) |

### What it detects

- AWS Access Key IDs (`AKIA…`) — with ±2 surrounding lines captured so you can **pair the ID with its secret key**, like the attacker's payload does
- GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)
- GitLab tokens (`glpat-`)
- Anthropic (`sk-ant-`), xAI (`xai-…`), OpenAI-style (`sk-…`) API keys
- Stripe-style secrets (`sk_live_…`) and generic high-entropy assignments (`db_password = "…"`)
- History-only leaks: secrets committed and later deleted are still found

## Example output

```markdown
# Secret rotation checklist

Repo: `/path/to/your/repo`
Scanned: 2026-10-16 21:00 UTC
Since: beginning of history
Findings: 2

## 1. AWS Access Key ID

- **Found in:** commit `a1b2c3d4e5f6` (2024-01-02) — `config/deploy.py`
- **Match:** `AKIAIOSFODNN7EXAMPLE`
- **Context (helps pair the secret with its key):**
```
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```
- **Suggested action:** Rotate via IAM immediately; invalidate the ID and audit CloudTrail.

## 2. GitHub token

- **Found in:** commit `b7c8d9e0f1a2` (2024-02-02) — `.env`
- **Match:** `ghp_abcdefghijklmnopqrstuvwxyz1234567890`
- **Context (helps pair the secret with its key):**
```
GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890
```
- **Suggested action:** Revoke in GitHub Settings > Developer settings; check audit log.
```

## Tests

```bash
python3 -m unittest discover -s tests -v   # 13 tests — builds a fixture git repo
                                            # with planted secrets across commits
                                            # (one deleted later) and verifies all
                                            # are found
```

## License

MIT — see [LICENSE](LICENSE).

## Built by Ingenious AI

This project is part of the **Ingenious AI** platform suite — defensive security tooling for the AI era. Our platforms are currently in early access (full launch Nov 1) — request access to any of them on WhatsApp:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI)
