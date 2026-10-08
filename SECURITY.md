# Security policy

## Read this before anything else

Every confinement claim castellan makes is **conditional on the agent being launched
through castellan**. It confines what *it* starts. A harness started any other way (a
plain binary in a terminal, a cron job, a second agent, a script that shells out) runs
completely unconfined, with your full filesystem and network access, and no castellan
process, ledger row or freeze will ever see it.

That is a design position, not a bug, and it is stated in full at the top of
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). The short version:

- Confidentiality is **not** in scope against other processes running as the same user.
  An unconfined same-uid sibling can read the event spine, trust state, other sessions'
  state and the keyring file. Closing that would require a second uid or a VM boundary.
  Those are architectural changes, not fixes.
- Integrity of the evidence rests on **Landlock write-denial**, not on the assumption that
  nothing else is running.
- `castellan siblings` makes an untagged harness process *visible*. It is advisory. It
  reports; it cannot prevent.

If you are evaluating whether this protects you, that boundary is the first question, not
the last.

## Supported versions

| Version | Supported |
|---------|-----------|
| v0.1.x on `quattro` | Yes |
| Anything older | No |

This is a small project maintained by one person. There is no backport queue.

## Scope

**In scope**: the code in this repository:

- the enforcement envelope (Landlock, seccomp, cgroups) and its audit/enforce postures
- the seccomp-notify egress broker and its policy decisions
- the credential-injecting egress proxy and the daemon keyring
- the trust engine, bless/broker approval flow, and canary handling
- the hash-chained certificate spine and its signing
- the daemon's RPC surface and the launcher's privilege hops

**Out of scope**: reporting these is a waste of your time:

- the harness itself (Claude Code, Codex, Pi, or any other agent). We confine them; we do
  not write them.
- behaviour of processes you did not launch through castellan (see the boundary above)
- kernel vulnerabilities, or bypasses requiring root
- anything needing physical access, or a hostile kernel
- social engineering of the human operator, including instructions embedded in agent output
- vulnerabilities in dependencies we do not control, unless our use of them is wrong

## How to report

**Use private vulnerability reporting.** On this repository, go to
**Security → Report a vulnerability**. That opens a private advisory thread visible only
to you and the maintainer, and it becomes the public record if and when you agree to
disclose.

Please do not open a public issue for a working bypass. That is the one request here.

If private reporting is unavailable to you for any reason, open an issue that says only
"security report available on request" with no detail, and it will be picked up.

I aim to acknowledge within a week. **There is no fix-time promise.** One maintainer, no
triage rota, no SLA. If a report needs work I cannot get to promptly, I will say so
plainly rather than let you wait on silence.

## What happens next

1. Acknowledge, and confirm whether the report reproduces on the current `quattro` tip.
2. Triage against the documented threat classes in
   [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): Threat A (the agent pulls its own
   levers), Threat B (the agent fakes evidence), Threat C (external actor). A report that
   lands outside those classes still gets a reply; it just may not be a bug.
3. Fix on the mainline through a PR, with the finding recorded in `docs/THREAT_MODEL.md`
   alongside the ones already there, including the ones that were found, closed, and
   that I got wrong the first time.
4. Disclose in the advisory thread after the fix lands, with your name on the credit line
   if you want it there.

Every adversarial finding so far was found by running attack batteries against my own
installations, and the record is public in
[docs/ATTACK_EXERCISE.md](docs/ATTACK_EXERCISE.md), including the batteries that found
nothing. Real bypasses have been fixed with live verification; the fixes are named in
the threat model.

## Testing policy

Attacking **castellan running on your own machine** is authorized and encouraged. That is
how this project finds its own bugs, and I would rather you found it first.

Attacking third-party systems is not. Do not use castellan's bypass classes against
infrastructure you do not own. Reports about that are not what this channel is for, and a
bypass proof-of-concept that lands on someone else's box is not research.

## Credit

Ask for it in the advisory thread. I would rather name you than not.

## Known limitations

The authoritative list is the residual risks summary in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Read that rather than trusting a summary
here: a copy in this file would drift out of date, and a stale security document is worse
than none. Nothing in castellan's documentation claims every attack class is closed,
and neither does this policy.

What is worth knowing up front: reads are broad, the seccomp filter is a denylist with a
default allow, and the boundaries that *are* enforced are enforced by the kernel rather
than by process-level checks. See the threat model for what follows from each.

There is no bug bounty program.