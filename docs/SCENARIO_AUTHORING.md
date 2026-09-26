# Writing Garrison scenarios

A scenario is one TypeScript module exporting a `Scenario` object (see `src/engine/types.ts`).
It does three things:

1. **Sets the scene** with `setup(world)` — mutate the cloned base world (`src/engine/world.ts`,
   company *Kestrel Dynamics*, domain `kestrel.local` / `kestreldynamics.com`). Add the locked-out
   flag, the malicious process, the phishing email, the SIEM events, the intel record, etc.
2. **Declares what a competent analyst does** as matchers over the **action log**: `evidence`
   (what they should look at), `required` (what they should do, optionally in order), `forbidden`
   (what they must not do), plus the reply choices, work-note rubric, and the closure form.
3. **Teaches** via `objective`, `hints`, and `debrief`.

Grading is purely a function of the action log + closure form. Every tool emits actions with a fixed
vocabulary (below). Use the vocabulary exactly.

## Action vocabulary

`{ tool, action, target?, params? }`. Targets are lower-cased when compared; regexes allowed.

### ticket (work panel)
| action | target | params |
|---|---|---|
| `open` | ticket/alert/incident number | |
| `set_priority` | | `{priority:'P1'..'P4'}` |
| `contact` | question id | `{purpose}` |
| `reply` | reply id | |
| `submit` | | |

### kb
| `search` | | `{q}` |
| `read` | article id e.g. `KB-0001` | |

### directory (target = user id unless noted)
`search {q}` · `view` · `view_signins` · `unlock` · `reset_password {mustChange}` · `enable` · `disable` ·
`add_group {group}` · `remove_group {group}` · `revoke_sessions` · `reset_mfa` · `set_display_name {name}` ·
`add_alias {alias}` · `view_group` (target = group name) · `view_computer` (target = host id) · `set_password_never_expires {value}`

### rdp (target = host id)
`connect` · `view_system` · `view_processes` · `end_process {name,pid}` · `view_services` · `start_service {service}` ·
`stop_service {service}` · `restart_service {service}` · `disable_service {service}` · `view_events {log}` ·
`view_programs` · `uninstall {program}` · `view_devices` · `update_driver {device}` · `rollback_driver {device}` ·
`enable_device {device}` · `view_network` · `set_dns {dns}` · `set_dhcp` · `view_tasks` · `delete_task {task}` ·
`view_files` · `quarantine_file {path}` · `view_updates` · `install_updates` · `reboot` · `run_scan` ·
`view_local_admins` · `remove_local_admin {member}` · `view_printers` · `remove_printer {printer}` ·
`add_printer {printer}` · `set_timezone {tz}` · `view_monitors` · `resume_bitlocker` · `view_browser_extensions` · `remove_extension {name}`

### terminal (target = host id; params.arg = first argument, params.cmd = whole line)
actions: `ipconfig` `ipconfig_all` `ipconfig_release` `ipconfig_renew` `ipconfig_flushdns` `ping` `tracert` `nslookup`
`netstat` `tasklist` `taskkill` `sfc` `dism` `gpupdate` `whoami` `whoami_groups` `systeminfo` `w32tm` `w32tm_resync`
`net_user` `dir` `schtasks` `sc_query` `sc_start` `sc_stop` `hostname`

### server (target = server id)
`view` · `view_services` · `start_service {service}` · `stop_service {service}` · `restart_service {service}` ·
`view_dhcp` · `extend_scope {scope}` · `reduce_lease {scope}` · `activate_scope {scope}` · `view_dns` ·
`add_dns_record {name,value}` · `delete_dns_record {name}` · `view_print_queues` · `resume_queue {queue}` · `clear_queue {queue}` ·
`pause_queue {queue}` · `view_shares` · `view_backups` · `restore {job}` · `view_events` · `reboot` · `view_processes` · `end_process {name}` · `view_disk` · `free_disk`

### assets
`search {q}` · `view` (target = tag) · `set_status {status}` · `assign {user}` · `unassign` · `dispatch_vendor` · `ship {user}` · `remote_wipe`

### mail
`trace {q}` · `view` (target = message id) · `view_headers` (target = message id) · `quarantine` (msg) · `release` (msg) ·
`purge_all` (msg) · `view_mailbox` (target = user id) · `remove_rule {rule}` (target = user id) · `remove_forwarding` (user) ·
`block_sender` (target = address or domain) · `raise_quota` (user) · `add_delegate {delegate}` (user) · `convert_shared` (user)

### chat
`open` (target = user id) · `send {text}` (target = user id)

### siem
`search {q}` · `pivot {field,value}` · `save_view {name}`

### edr (target = host id)
`view_host` · `view_alerts` · `view_tree {process}` · `view_timeline` · `isolate` · `release` · `kill_process {name}` ·
`quarantine_file {path}` · `collect_triage` · `view_network` · `scan`

### intel
`lookup` (target = indicator)

### perimeter
`view_rules` · `block {where:'firewall'|'proxy'|'email'|'dns'}` (target = indicator) · `unblock` (target)

### incident (CIRT)
`set_phase {phase}` · `set_severity {severity}` · `add_timeline {text}` · `add_ioc` (target = indicator) ·
`add_scope` (target = host or user) · `notify` (target = stakeholder id) · `reimage` (target = host) ·
`restore_backup {job}` (target = host/server) · `rotate_krbtgt` · `reset_service_account` (target = user) · `engage_retainer` · `legal_hold`

Stakeholder ids for `notify`: `it_director`, `executives`, `legal`, `hr`, `finance`, `affected_users`, `all_staff`,
`insurance`, `law_enforcement`, `customers`, `regulator`, `vendor`, `plant_ops`.

## Ticket form fields the trainee fills

priority · work notes (free text, graded by regex rubric) · reply (choose one of your `replies`) ·
disposition (`resolve` | `escalate` | `reject`) + escalateTo · category · resolution code ·
SOC: classification + severity · CIRT: notifications (checkboxes) + incident report (free text, graded by `closure.reportFields`).

## Conventions

- Ticket numbers: `INC` + 6 digits; alerts `ALT-` + 5 digits; incidents `IR-2026-` + 3 digits.
- Timestamps: use `ago(minutes)` / `daysAgo(days)` from `world.ts`; "now" is `2026-09-15T09:12:00`.
- Hidden ground truth fields (`phishing`, `truth`, `suspicious`) are never shown to the trainee; use them freely.
- Every scenario should have **at least one red herring** (a benign warning event, an unrelated stale process, a benign DCOM 10016 event) so trainees learn to discriminate.
- `contact` questions: give 5–8, with 2 `verify` (employee ID, callback/manager), 2–4 `clarify`, 1–2 `irrelevant`, and optionally a `red_flag` one for social engineering.
- `replies`: 3–4 options; exactly one `best: true`. Score each on `communication` (0–1) and, where relevant, `security` / `process`.
- `notesRubric`: 3–5 regex rules on the work notes (cause, action, verification, escalation details).
- Escalation is a valid *correct* answer. Roughly one in four scenarios should not be resolvable at the trainee's tier.
- Order matters where it matters: use `after`/`before` on required actions (e.g. `collect_triage` before `reimage`).
- Keep `estMinutes` honest: 6–10 for SD1, 10–15 for SD2/SOC1, 15–20 for SOC2, 20–30 for CIRT.

## Randomization (optional)

Add `tokens` to a scenario to rotate memorizable indicators each attempt. Each
token's `from` literal is replaced everywhere it appears (world data, intake,
matchers, replies, hints, rubric) by `gen(rand)`:

```ts
import { randIp, randDomain, randHash } from '../engine/instantiate';
// on the Scenario:
tokens: [
  { from: '45.146.164.90', gen: randIp },      // C2 IP
  { from: 'cdn-updates.xyz', gen: randDomain }, // callback domain
  { from: 'c1d2...ab', gen: randHash },         // dropped-file hash
],
```

Rules of thumb: only tokenize *indicators* (IPs, domains, hashes) — not the cast
(users/hosts) or internal asset IPs — and make each `from` a unique, exact string.
The correct decision must stay the same regardless of the value. `npm run validate`
runs tokenized scenarios across several seeds and fails if any variant becomes
uncompletable or grades wrong, so add tokens and re-run the validator.
