# Security Automation at Scale: Leveraging Ansible for Implementing CIS Hardening

**Event**: [Cyber Security Challenge Greece 2026](https://cybersecuritychallenge.gr/)

**Goal**: Understand what Ansible is, how security benchmarks work, and see live automated hardening of different Linux systems running in parallel.

**Author**: [Christos Karamolegkos](https://www.ckaramolegkos.gr), Manager, Systems & Infrastructure, Power Factors 

This guide is self-contained — you can follow it during the live workshop or work through it independently at your own pace.

---

## Lab Environment

| Host | OS | Role |
|------|----|------|
| `ansible-controller` | Debian 12.1 | Ansible Controller — all commands run here; also hardened |
| `debian-target` | Debian 12.1 | Hardening target |
| `ubuntu-target` | Ubuntu 22.04 LTS | Hardening target |

**Roles used**:
- [`DEBIAN12-CIS`](https://github.com/ansible-lockdown/DEBIAN12-CIS) — CIS Debian 12 Benchmark v1.1.0
- [`UBUNTU22-CIS`](https://github.com/ansible-lockdown/UBUNTU22-CIS) — CIS Ubuntu 22 Benchmark v2.0.0

---

## Setup Checklist

- [ ] 3 VMs provisioned: 1× Debian 12.1 (Ansible Controller), 1× Debian 12.1 (target), 1× Ubuntu 22.04 (target)
- [ ] Both target VMs reachable from the Ansible Controller over SSH
- [ ] Initial OS user on each target has passwordless sudo (default on cloud/VM images)
- [ ] Ansible Controller has internet access to install packages and download roles/Goss binary
- [ ] IP addresses filled in under `inventory/host_vars/` for the two targets (`debian-target.yml`, `ubuntu-target.yml`)
- [ ] **Snapshots taken of all three VMs** — allows fast reset between runs or if something goes wrong
- [ ] CIS Benchmark PDFs pre-downloaded for reference (Debian 12, Ubuntu 22)

---

## Contents

1. [Introduction](#1-introduction)
2. [Core Concepts](#2-core-concepts)
3. [Setting Up the Ansible Controller](#3-setting-up-the-ansible-controller)
4. [Understanding the Roles](#4-understanding-the-roles)
5. [Pre-Hardening Audit — Establishing a Baseline](#5-pre-hardening-audit--establishing-a-baseline)
6. [Hardening Both Targets in Parallel](#6-hardening-both-targets-in-parallel)
7. [Post-Hardening Audit — Measuring the Impact](#7-post-hardening-audit--measuring-the-impact)
8. [Idempotency Demo](#8-idempotency-demo)

---

## 1. Introduction

### The problem we're solving

Imagine you need to harden 500 Linux servers to comply with a security standard. Doing it manually means:

- Hundreds of configuration files to edit on every single machine
- No guarantee that each machine ends up in the same state
- Any change needs to be applied to all machines again
- A month of work that needs to be repeated every time a new server is deployed

This workshop shows how Ansible and community-built security roles turn that month of work into a single command that runs in parallel across all your targets.

### What you will walk away with

- A mental model of how Ansible works
- An understanding of what CIS benchmarks are and why they matter
- Hands-on experience running automated hardening against two different Linux distributions simultaneously
- An intuition for what "idempotency" means and why it is essential in automation

---

## 2. Core Concepts

### 2.1 What is Ansible?

Ansible is an open-source **automation tool** that lets you describe the desired state of a system using plain YAML files and then push that configuration to any number of remote machines over SSH — without installing any agent software on them.

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Ansible Controller                           │
│                                                                      │
│  ansible.cfg ─────────────────────────────────────────────────────── │
│    defines Ansible configuration like where the inventory is,        │
│     how many hosts in parallel, and that SSH pipelining is enabled   │
│                                                                      │
│  inventory/                                                          │
│    hosts.yml ─────────────────────────────────────────────────────── │
│      defines host groups: cis > cis_level1, cis_level2               │
│    group_vars/all.yml ────────────────────────────────────────────── │
│      vars applied to every host (ansible_user, skip_reboot, …)       │
│    group_vars/cis_level1.yml ─────────────────────────────────────── │
│      vars applied to the cis_level1 group (level flags)              │
│    host_vars/debian-target.yml ───────────────────────────────────── │
│      vars applied to that one host only (overrides group defaults)   │
│                                                                      │
│  playbooks/                                                          │
│    bootstrap.yml ─────────────────────────────────────────────────── │
│      one-time: creates the ansible service account on each target    │
│    audit.yml ─────────────────────────────────────────────────────── │
│      read-only compliance check via Goss; fetches JSON reports       │
│    harden.yml ────────────────────────────────────────────────────── │
│      applies CIS hardening then runs the audit                       │
│                                                                      │
│  roles/                                                              │
│    DEBIAN12-CIS/ ─────────────────────────────────────────────────── │
│      tasks implementing the CIS Debian 12 benchmark                  │
│    UBUNTU22-CIS/ ─────────────────────────────────────────────────── │
│      tasks implementing the CIS Ubuntu 22 benchmark                  │
└────────────────────────────────────┬─────────────────────────────────┘
                                     │  SSH (parallel, no agent)
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
       ┌────────────────────┐           ┌────────────────────┐
       │    debian-target   │           │   ubuntu-target    │
       │    Debian 12.1     │           │   Ubuntu 22.04     │
       │    CIS Level 1     │           │   CIS Level 1      │
       └────────────────────┘           └────────────────────┘
```

**Key properties**:

| Property | What it means |
|----------|---------------|
| **Agentless** | Nothing is installed on the managed hosts — Ansible uses SSH |
| **Declarative** | You describe *what* you want, not *how* to get there |
| **Idempotent** | Running the same playbook twice produces the same result — no double-changes |
| **Parallel** | By default, Ansible operates on multiple hosts at the same time |

### 2.2 Core Ansible building blocks

**Inventory** — a list of hosts (and groups of hosts) to manage. In this workshop, hosts are grouped by the CIS level we want to enforce — not by OS. The playbook discovers each host's OS at runtime and applies the correct role automatically (more on this in [Section 3.4](#34-inventory-format--ini-vs-yaml) and [Section 4](#4-understanding-the-roles)):

```yaml
all:
  children:
    cis_level1:
      hosts:
        debian-target:
        ubuntu-target:
    cis_level2:
      hosts:
        # add hosts here when ready for deeper hardening
```

**Task** — a single action (install a package, edit a file, restart a service):

```yaml
- name: Ensure SSH root login is disabled
  ansible.builtin.lineinfile:
    path: /etc/ssh/sshd_config
    regexp: '^PermitRootLogin'
    line: 'PermitRootLogin no'
```

**Playbook** — an ordered list of tasks to run against one or more groups of hosts:

```yaml
- name: My first playbook
  hosts: all
  become: true   # run as root via sudo
  tasks:
    - name: Install git
      ansible.builtin.apt:
        name: git
        state: present
```

**Role** — a reusable, structured collection of tasks, variables, and templates packaged together. Think of it as a library someone else wrote that you plug into your playbook.

### 2.3 What is idempotency and why does it matter?

Run a playbook once: Ansible makes the necessary changes and reports them as `changed`.

Run the exact same playbook again immediately: Ansible checks the current state, sees it already matches what you asked for, and reports `ok` — **zero changes made**.

This is critical in operations because it means:
- You can safely re-run a playbook to recover from drift
- Running it again on a compliant system does no harm
- You can run it in a CI/CD pipeline every time you deploy a new server

Section 8 demonstrates this with a live run after the hardening step.

### 2.4 What is a CIS Benchmark?

The **Center for Internet Security (CIS)** is a non-profit that publishes free hardening guides — called **benchmarks** — for operating systems, cloud services, and applications. These benchmarks are authored by a community of security experts and represent consensus best practices.

Each benchmark contains hundreds of **controls** — specific configuration checks — organized into two levels:

| Level | Description | Use case |
|-------|-------------|----------|
| **Level 1** | Essential hardening. Minimal operational impact. | Recommended starting point for all systems |
| **Level 2** | Deeper hardening. May break certain functionality. | High-security environments; requires careful review |

**Example controls from CIS Debian 12**:

- `1.1.2` — Ensure `/tmp` is configured as a separate partition
- `5.2.8` — Ensure SSH root login is disabled
- `5.4.2` — Ensure password creation requirements are configured
- `6.1.1` — Ensure permissions on `/etc/passwd` are configured

### 2.5 CIS vs. STIG

Another hardening framework you may encounter is **DISA STIG** (Security Technical Implementation Guide), published by the US Department of Defense for US government and military systems. CIS and STIG cover much of the same ground — a CIS Level 2 hardened system will pass a large portion of STIG controls — but STIG is more rigid and mandated specifically for US government contractors. For most organizations outside that context, **CIS benchmarks are the practical choice**: they are community-driven, freely available as PDFs, and supported by a wide ecosystem of automation tooling including ansible-lockdown.

### 2.6 What is ansible-lockdown?

[ansible-lockdown](https://github.com/ansible-lockdown) is an open-source project that provides ready-made Ansible roles implementing CIS and STIG benchmarks for many operating systems. Rather than writing all the automation yourself, you plug in their role and configure a few variables.

For this workshop:
- **DEBIAN12-CIS** — implements CIS Debian 12 Benchmark v1.1.0 (~280 controls)
- **UBUNTU22-CIS** — implements CIS Ubuntu 22 Benchmark v2.0.0

Both roles also include **Goss** integration — a lightweight binary that runs the same controls in read-only audit mode and produces a compliance score report.

---

## 3. Setting Up the Ansible Controller

All commands in this section run on the **Ansible Controller** VM.

### 3.1 Install Ansible

```bash
sudo apt update
sudo apt install -y python3 python3-pip git
pip3 install --user ansible argcomplete passlib
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
activate-global-python-argcomplete --user
source ~/.bashrc
ansible --version
```

Confirm the output shows `ansible [core 2.12+]`.

**argcomplete** provides tab-completion for all Ansible CLI tools (`ansible`, `ansible-playbook`, `ansible-galaxy`, etc.). `activate-global-python-argcomplete --user` installs a completion hook into `~/.bash_completion.d/` and sources it from `.bashrc` — after reloading the shell you can press Tab to complete hostnames, playbook paths, tags, and module names.

> **Production note — Execution Environments**: Installing Ansible via `pip` is appropriate for workshops and local development, but in production the recommended approach is **Execution Environments (EEs)** — container images that bundle a specific version of Ansible, all required collections, roles, and Python dependencies into a single reproducible artifact. EEs are the standard unit of execution in **AWX** and **Ansible Automation Platform (AAP)** and are built with `ansible-builder`. They eliminate dependency drift between operators and make automation portable across CI/CD pipelines and machines.

### 3.2 Configure passwordless SSH to both targets

```bash
# Generate a key pair (press Enter to accept defaults)
ssh-keygen -t ed25519 -C "workshop-controller"

# Copy the public key to both targets
ssh-copy-id user@debian-target
ssh-copy-id user@ubuntu-target
```

Test that passwordless login works:

```bash
ssh user@debian-target hostname
ssh user@ubuntu-target hostname
```

> **Best practice — dedicated service account**: For any real deployment it is strongly recommended to create a dedicated OS account (`ansible`) for automation operations on every managed node. A dedicated account makes audit logs unambiguous, simplifies key rotation, and limits blast radius if credentials are compromised. The full setup is automated by `playbooks/bootstrap.yml` — see **section 3.9** for the walkthrough.

### 3.3 Clone this repository

```bash
git clone <this-repo-url> ~/AnsibleLockdownWorkshopCSCGR2026
cd ~/AnsibleLockdownWorkshopCSCGR2026
```

The repository uses the standard Ansible directory layout:

```
AnsibleLockdownWorkshopCSCGR2026/
├── ansible.cfg                    # Ansible configuration
├── requirements.yml               # Role and collection dependencies
├── inventory/
│   ├── hosts.yml                  # Host inventory — grouped by CIS level
│   ├── group_vars/
│   │   ├── all.yml                # Vars applied to every host
│   │   ├── cis_level1.yml         # Vars for CIS Level 1 group
│   │   └── cis_level2.yml         # Vars for CIS Level 2 group
│   └── host_vars/
│       ├── ansible-controller.yml # Per-host overrides for the Ansible Controller
│       ├── debian-target.yml      # Per-host overrides for debian-target
│       └── ubuntu-target.yml      # Per-host overrides for ubuntu-target
├── playbooks/
│   ├── bootstrap.yml              # One-time: create the ansible service account
│   ├── audit.yml                  # Read-only compliance audit
│   └── harden.yml                 # Apply CIS hardening + audit
├── reports/                       # Goss JSON reports (gitignored)
└── roles/                         # Hardening roles — installed via ansible-galaxy
    ├── DEBIAN12-CIS/
    └── UBUNTU22-CIS/
```

This is the standard layout used for real production Ansible projects. Keeping inventory, playbooks, and group/host variables in separate directories makes the project navigable as it grows to hundreds of hosts and dozens of playbooks.

### 3.4 Inventory format — INI vs YAML

Ansible supports two inventory formats. Both are fully equivalent — choose whichever fits your team's conventions.

**INI format** — compact, familiar to anyone who has worked with config files:

```ini
[cis:children]
cis_level1
cis_level2

[cis_level1]
debian-target
ubuntu-target

[cis_level2]
# empty for now
```

**YAML format** — more verbose but consistent with the rest of Ansible (playbooks, vars files, and role defaults are all YAML). Easier to read as inventories grow, and works better with linters and IDE tooling:

```yaml
all:
  children:
    cis:
      children:
        cis_level1:
          hosts:
            debian-target:
            ubuntu-target:
        cis_level2:
          hosts:
```

**Which to choose**: Use **YAML** for new projects — it is consistent with the rest of the Ansible ecosystem and scales better. Use INI for quick one-off inventories or when working with an existing codebase that already uses it.

Neither format mentions the OS. Hosts are grouped by **desired hardening level** and the `cis` parent gives playbooks a single group to target. When you add a new server, you only decide which level applies — the playbook handles OS detection automatically.

### 3.5 Variable layering with group_vars and host_vars

One of Ansible's most powerful features is its **variable precedence system**. Variables defined closer to a specific host win over more general ones:

```
group_vars/all.yml          ← applies to every host
      │
      ▼  (overridden by)
group_vars/cis_level1.yml   ← applies to hosts in [cis_level1]
      │
      ▼  (overridden by)
host_vars/debian-target.yml ← applies only to debian-target
```

In this workshop:

| File | What it controls |
|------|-----------------|
| `group_vars/all.yml` | Connection user, Python path, shared role settings (skip_reboot, disruption_high, auditd exclusions) |
| `group_vars/cis_level1.yml` | Sets `level1: true`, `level2: false` for both OS roles |
| `group_vars/cis_level2.yml` | Sets `level1: true`, `level2: true` for both OS roles |
| `host_vars/debian-target.yml` | `ansible_user: debian` (pre-bootstrap) — and any per-host exceptions |
| `host_vars/ubuntu-target.yml` | `ansible_user: ubuntu` (pre-bootstrap) — and any per-host exceptions |

**Practical example**: If one server runs a legacy application that breaks when a specific CIS control is applied, you can disable just that control for that one host in its `host_vars` file — without touching the group policy or any other server.

### 3.6 Review ansible.cfg

```ini
# ansible.cfg
[defaults]
inventory         = inventory   # Ansible reads hosts.yml + group_vars/ + host_vars/
roles_path        = roles
host_key_checking = False
forks             = 5           # operate on this many hosts simultaneously

[ssh_connection]
pipelining        = True        # pipe module code over SSH instead of transferring files
```

Pointing `inventory` at a directory (not a file) tells Ansible to read all inventory files in that directory and automatically pick up the `group_vars/` and `host_vars/` subdirectories sitting next to them.

**On pipelining**: Normally Ansible transfers each module as a temporary file via SFTP, then opens a second SSH connection to execute it. With `pipelining = True` the module code is piped over the existing SSH connection directly — no file transfer, one round trip. The CIS roles run 200+ tasks per host, so this gives a meaningful speed boost (typically 2–5× faster). The only requirement is that `Defaults requiretty` must **not** be in `/etc/sudoers` — Debian 12 and Ubuntu 22.04 don't set it, so this is safe here.

### 3.7 Install the hardening roles via Ansible Galaxy

The project declares its role and collection dependencies in `requirements.yml`. Install them all with one command:

```bash
cd ~/AnsibleLockdownWorkshopCSCGR2026
ansible-galaxy install -r requirements.yml -p roles/
```

This fetches both roles from GitHub and places them in `roles/DEBIAN12-CIS/` and `roles/UBUNTU22-CIS/`, exactly where `ansible.cfg` expects them.

**Why `ansible-galaxy` instead of `git clone`?**

| | `git clone` | `ansible-galaxy install` |
|---|---|---|
| Dependency declaration | Manual, in a README | Machine-readable `requirements.yml` |
| Reproducibility | Relies on documentation | Anyone can re-install with one command |
| Version pinning | Specify a branch in the command | Pin with `version:` in requirements.yml |
| CI/CD friendly | Requires scripting | Native support in pipelines |

The `roles/` directory remains gitignored — roles are a dependency of this project, not part of it. If you pin a specific `version:` tag in `requirements.yml`, the exact same role code is installed everywhere.

### 3.8 Verify connectivity to all hosts

```bash
cd ~/AnsibleLockdownWorkshopCSCGR2026
ansible all -m ping
```

Expected output:

```
ansible-controller | SUCCESS => { "ping": "pong" }
debian-target      | SUCCESS => { "ping": "pong" }
ubuntu-target      | SUCCESS => { "ping": "pong" }
```

At this point Ansible is connecting to the two remote targets as the initial OS user (`debian` / `ubuntu`) declared in their `host_vars` files. The Ansible Controller responds immediately via `ansible_connection: local` without an SSH hop. Confirming connectivity here before running bootstrap confirms that the SSH keys and sudo access are working correctly.

### 3.9 Bootstrap the Ansible service account

The `bootstrap.yml` playbook creates a dedicated `ansible` OS account on every managed node, grants it passwordless sudo, and authorises only the controller's SSH public key on it — automatically, in parallel across all hosts.

```bash
ansible-playbook playbooks/bootstrap.yml
```

What the playbook does:

1. Creates the `ansible` OS user with a home directory
2. Drops `/etc/sudoers.d/ansible` granting `NOPASSWD: ALL` (validated with `visudo` before placement — a malformed file is rejected, not written)
3. Uses `ansible.posix.authorized_key` with `exclusive: true` to add the controller's public key and remove any other keys from the account

The controller's public key is read automatically from `~/.ssh/id_ed25519.pub`. To use a different key, pass `-e bootstrap_pubkey_path=/path/to/other.pub`.

This is a real-world onboarding pattern — the first thing a new-server provisioning pipeline does is create and lock down the automation account. Doing it with Ansible (rather than a bash script or manually) means it is idempotent, auditable, and version-controlled.

### 3.10 Switch over to the ansible account

Now that the service account exists, update the inventory so all subsequent playbooks connect as `ansible` instead of the initial OS users.

In each of the three `host_vars` files — `ansible-controller.yml`, `debian-target.yml`, and `ubuntu-target.yml` — comment out the `ansible_user` line:

```yaml
# ansible_user: debian   ← comment this out
```

The `group_vars/all.yml` default (`ansible_user: ansible`) now takes over for every host. The Ansible Controller bootstraps itself with `ansible_connection: local`, so the account is created on the controller machine as well.

Verify the switch worked:

```bash
ansible all -m ping
```

The output should be identical to before — same hosts, same result — but Ansible is now connecting as the `ansible` account on each target. This is the user all hardening and audit runs will execute as from this point forward.

---

## 4. Understanding the Roles

### 4.1 Role directory structure

```
DEBIAN12-CIS/
├── defaults/main.yml    ← All configurable variables with their defaults
├── tasks/
│   ├── main.yml         ← Entry point — imports each section
│   ├── section1/        ← CIS Section 1: Filesystem Configuration
│   ├── section2/        ← CIS Section 2: Services
│   ├── section3/        ← CIS Section 3: Network Configuration
│   ├── section4/        ← CIS Section 4: Logging & Auditing
│   ├── section5/        ← CIS Section 5: Access, Auth & Authorization
│   └── section6/        ← CIS Section 6: System Maintenance
├── handlers/main.yml    ← Triggered actions (restart sshd, reload firewall...)
├── templates/           ← Jinja2 config file templates
└── vars/main.yml        ← Internal OS-specific variables
```

### 4.2 Key variables to configure

Open `roles/DEBIAN12-CIS/defaults/main.yml` and review:

```yaml
# Run the Goss audit after applying hardening?
run_audit: false

# Which benchmark level to apply?
debian12cis_level1: true
debian12cis_level2: false

# Skip controls that have a high chance of breaking services?
debian12cis_disruption_high: false

# Don't reboot automatically even if required by a control
debian12cis_skip_reboot: true
```

`defaults/main.yml` is where you customize the role's behavior. Always read through it before running in production — many controls are disabled by default because they require environment-specific decisions.

### 4.3 How the playbooks select the right role

Both playbooks use `include_role` with `when` conditions based on `ansible_distribution` — a fact Ansible collects from each host at the start of the play. This means **a single playbook handles all OS types without any per-OS branching in the inventory**.

```yaml
# playbooks/harden.yml
- name: CIS Hardening
  hosts: cis                  # ← targets all hosts across cis_level1 and cis_level2
  become: true
  gather_facts: true          # ← collects ansible_distribution on every host
  tasks:

    - name: Apply DEBIAN12-CIS hardening
      ansible.builtin.include_role:
        name: DEBIAN12-CIS
      when:
        - ansible_distribution == "Debian"
        - ansible_distribution_major_version == "12"

    - name: Apply UBUNTU22-CIS hardening
      ansible.builtin.include_role:
        name: UBUNTU22-CIS
      when:
        - ansible_distribution == "Ubuntu"
        - ansible_distribution_major_version == "22"
```

**What happens when Ansible runs this against `debian-target`**:
1. Connects over SSH, collects facts → `ansible_distribution = "Debian"`, `ansible_distribution_major_version = "12"`
2. Evaluates the first `when` → `true` → runs `DEBIAN12-CIS`
3. Evaluates the second `when` → `false` → skips `UBUNTU22-CIS`

**What happens for `ubuntu-target`**:
1. Collects facts → `ansible_distribution = "Ubuntu"`, `ansible_distribution_major_version = "22"`
2. First `when` → `false` → skips `DEBIAN12-CIS`
3. Second `when` → `true` → runs `UBUNTU22-CIS`

The level variables (`level1`, `level2`, `disruption_high`, etc.) come from `group_vars/cis_level1.yml` automatically via inheritance — the playbook itself has no hardcoded level settings. A host in `cis_level2` will receive `level2: true` from its group_vars, and the same playbook will apply deeper hardening without any code change.

**audit.yml** works identically, but overrides `audit_only: true` at the play level to suppress all remediation tasks, regardless of what any group_vars say:

```yaml
- name: CIS Compliance Audit
  hosts: cis
  become: true
  gather_facts: true
  vars:
    audit_only: true   # play vars override group_vars — no changes made
  tasks:
    - name: Audit with DEBIAN12-CIS
      ansible.builtin.include_role:
        name: DEBIAN12-CIS
      when:
        - ansible_distribution == "Debian"
        - ansible_distribution_major_version == "12"
    # ... same pattern for Ubuntu
```

> **Scaling insight**: To onboard a new server, add one line to `hosts.yml` under the right CIS level group. The playbooks, roles, and group_vars need no changes — the automation scales horizontally without touching any logic.

### 4.4 Disabling specific controls

Every CIS control in a role can be disabled individually by setting its variable to `false`. This is the primary mechanism for tailoring hardening to your environment without forking the role.

**Variable naming convention**:

```
<role_prefix>_rule_<section>_<subsection>[_<item>]: false
```

For example, to disable CIS Debian 12 rule 5.2.20 ("Ensure SSH MaxSessions is limited"):

```yaml
debian12cis_rule_5_2_20: false
```

**Where to place these overrides**:

| Scope | Where |
|---|---|
| All hosts in a group | `inventory/group_vars/cis_level1.yml` |
| A single host | `inventory/host_vars/<hostname>.yml` |
| A single playbook run | `-e "debian12cis_rule_5_2_20=false"` on the command line |

`inventory/group_vars/cis_level1.yml` contains commented examples of common per-control exclusions. `inventory/host_vars/ansible-controller.yml` shows exclusions appropriate for the controller itself (SSH session limits, filesystem controls that interfere with container workloads).

> The rule variable names come directly from the CIS benchmark numbering. Open `roles/DEBIAN12-CIS/defaults/main.yml` and search for `rule_` to see the full list of toggleable controls and the descriptions next to each one.

### 4.5 The standalone -Audit roles — and why we don't use them here

Alongside the main `DEBIAN12-CIS` and `UBUNTU22-CIS` roles, ansible-lockdown publishes separate `DEBIAN12-CIS-Audit` and `UBUNTU22-CIS-Audit` roles. These are **audit-only** — they install Goss and run a compliance check but make **no system changes at all**.

We do not need them in this workshop because the main CIS roles include the same Goss-based audit capability built in, controlled by two variables already set in `group_vars/all.yml`:

```yaml
run_audit: true                   # run the Goss compliance check after the role finishes
setup_audit: true                 # install the Goss binary on each target
get_audit_binary_method: copy     # copy from controller instead of downloading on each target
audit_bin_copy_location: /tmp     # where the pre-play staged the binary on the controller
```

With `run_audit: true`, the main role runs the audit as its final step. Setting `audit_only: true` (which `audit.yml` does at the play level) skips all remediation and runs only the audit — effectively turning the main role into an audit-only tool. There is no need to install or maintain a separate role.

**When you would reach for the standalone -Audit roles**:
- You are auditing systems that were hardened by a different tool or manually — the main role has nothing to remediate and the standalone role is lighter
- Your security and operations teams are separated: operations applies hardening, security independently audits without being able to trigger remediation
- You want to audit systems that are not in scope for the main role (e.g. a role exists for Debian 12 but not yet for another OS you need to assess)

---

## 5. Pre-Hardening Audit — Establishing a Baseline

Before touching anything, generate a compliance report for all three hosts. This gives the "before" snapshot to compare against after hardening.

### 5.1 Run the audit playbook

```bash
cd ~/AnsibleLockdownWorkshopCSCGR2026
ansible-playbook playbooks/audit.yml
```

Ansible runs against all three hosts in the `cis` group **in parallel** — including the Ansible Controller itself, which uses a local connection. The output shows tasks interleaved from all hosts, each prefixed with the host name.

What happens during the run:
- A first play downloads the Goss binary to the Ansible Controller (`/tmp/goss-linux-AMD64`). This is the only step that requires outbound internet access — the targets themselves never reach out.
- The CIS roles copy the binary from the controller to `/usr/local/bin/goss` on each target (`get_audit_binary_method: copy` in `group_vars/all.yml`)
- Goss checks each CIS control against the current system state
- No configuration files are modified — this is purely read-only

### 5.2 Reports are fetched automatically

The audit playbook's `post_tasks` create a per-host subdirectory under `reports/` and fetch the Goss JSON report automatically at the end of each run. No manual step is needed.

After the playbook completes you will have:

```
reports/
├── ansible-controller/
│   └── goss_report_20260311T105200Z.json
├── debian-target/
│   └── goss_report_20260311T105200Z.json
└── ubuntu-target/
    └── goss_report_20260311T105200Z.json
```

The timestamp in each filename is `ansible_date_time.iso8601_basic_short` — collected from the host at the start of the play, so all reports from the same run share a consistent timestamp and are easy to sort.

### 5.3 Read the scores

```bash
# Quick summary from each report
python3 -c "
import json, glob
for f in sorted(glob.glob('reports/**/*.json', recursive=True)):
    d = json.load(open(f))
    s = d.get('summary', {})
    host = f.split('/')[1]
    print(f'{host}: passed={s.get(\"test-count-passed\",\"?\")}, failed={s.get(\"test-count-failed\",\"?\")}, total={s.get(\"test-count\",\"?\")}')
"
```

**Expected output** (fresh install, no hardening applied):

```
ansible-controller: passed=42,  failed=238, total=280
debian-target:      passed=42,  failed=238, total=280
ubuntu-target:      passed=46,  failed=234, total=280
```

A vanilla OS installation fails the vast majority of CIS controls. This is expected — these controls represent hardening choices that are deliberately not applied by default because they could break general-purpose workloads. Note these numbers down to compare against the post-hardening scores in Section 7.

### 5.4 Visualizing the reports

The Goss output is a JSON file. Unlike `oscap` which produces a styled HTML report out of the box, Goss does not render HTML by default — but there are several practical options:

**Option 1 — `jq` (quickest, no extra tools)**

```bash
# List all failed checks for a specific host
jq '[.results[] | select(.successful == false) | {title: .title, resource_type: .resource_type}]' \
  reports/debian-target/goss_report_*.json

# Count: total / passed / failed
jq '.summary | {total: .["test-count"], passed: .["test-count-passed"], failed: .["test-count-failed"]}' \
  reports/debian-target/goss_report_*.json
```

**Option 2 — Goss `--format` flags (run directly on the host)**

When running `goss validate` interactively on the target, these formats are available:

```bash
# rspecish — concise pass/fail per control, similar to RSpec test output
goss --gossfile /path/to/goss.yml validate --format rspecish

# documentation — verbose, one line per check with full descriptions
goss --gossfile /path/to/goss.yml validate --format documentation
```

These are useful for spot-checking a single host directly, but don't produce a file you can share or archive.

**Option 3 — Goss built-in HTML output (goss ≥ v0.4.0)**

Newer versions of Goss support `--format html`, producing a styled, self-contained HTML report:

```bash
goss --gossfile /path/to/goss.yml validate --format html > report.html
```

Check the version bundled with the role (`goss --version`) before relying on this — the ansible-lockdown roles bundle their own Goss binary, and if it predates v0.4.0 this flag is unavailable.

**Option 4 — Enterprise / long-term storage**

The JSON reports can be ingested by any log aggregation or observability platform:

- **ELK / OpenSearch** — index reports as documents; build Kibana dashboards showing pass/fail trends over time
- **Grafana + Loki** — parse JSON and plot compliance scores across hosts and over time
- **Splunk** — ingest JSON directly; the `test-count-failed` field becomes a metric

> **Comparison with `oscap`**: OpenSCAP produces a rich HTML report because the XCCDF/OVAL formats are purpose-built for compliance reporting and have mature tooling. Goss is a general-purpose server testing tool — its strength is speed and simplicity, not report presentation. For long-term compliance tracking, the right answer is to forward the Goss JSON into a centralized platform rather than relying on per-run HTML files.

---

## 6. Hardening Both Targets in Parallel

Now apply CIS Level 1 hardening to both hosts with a single command.

### 6.1 Run the hardening playbook

```bash
cd ~/AnsibleLockdownWorkshopCSCGR2026
ansible-playbook playbooks/harden.yml
```

Both hosts run simultaneously — task output is interleaved from `debian-target` and `ubuntu-target`. Here is what each task status colour means:

- `changed` (yellow) — Ansible found a non-compliant configuration and fixed it
- `ok` (green) — the system was already in the correct state, nothing done
- `skipped` (light blue) — not applicable to this system or disabled via a variable

**Sections you will see scroll by**:

| Section | What is being hardened |
|---------|------------------------|
| Section 1 | Filesystem: partitions, mount options, disabled kernel modules |
| Section 2 | Services: disable unused daemons (rpcbind, avahi, cups, etc.) |
| Section 3 | Network: kernel sysctl hardening, IPv6 settings, firewall rules |
| Section 4 | Audit logging: auditd rules, journald configuration, log permissions |
| Section 5 | SSH hardening, PAM, password policies, sudo rules, user accounts |
| Section 6 | File permissions on sensitive system files |

**Estimated runtime**: 8–12 minutes for CIS Level 1 on both hosts.

After the playbook finishes, Ansible prints a **play recap** summarizing all changes:

```
PLAY RECAP ************************************************************
debian-target : ok=182  changed=97   unreachable=0  failed=0
ubuntu-target : ok=176  changed=103  unreachable=0  failed=0
```

The high `changed` count is normal on a fresh system — the role found and remediated a large number of non-compliant configurations.

### 6.2 Manual spot-checks

SSH into one of the targets and verify a handful of well-known controls directly:

```bash
ssh ansible@debian-target

# CIS 5.2.8 — SSH root login disabled?
sshd -T | grep permitrootlogin

# CIS 5.2.11 — SSH X11 forwarding disabled?
sshd -T | grep x11forwarding

# CIS 5.4.2 — Password max age set?
grep "^PASS_MAX_DAYS" /etc/login.defs

# CIS 2.1 — Is rpcbind disabled?
systemctl is-enabled rpcbind 2>/dev/null || echo "not installed/enabled"

exit
```

These are a small sample of the ~280 controls the role applied. Each one corresponds to a numbered entry in the CIS Debian 12 Benchmark PDF.

---

## 7. Post-Hardening Audit — Measuring the Impact

Run the same audit from Section 5 again — against the now-hardened systems — to see how the scores changed.

### 7.1 Run the audit again

```bash
cd ~/AnsibleLockdownWorkshopCSCGR2026
ansible-playbook playbooks/audit.yml
```

### 7.2 Compare the reports

The `reports/` directory now contains two timestamped reports per host — one from before hardening, one from after. Compare the scores:

```bash
python3 -c "
import json, glob
for f in sorted(glob.glob('reports/**/*.json', recursive=True)):
    d = json.load(open(f))
    s = d.get('summary', {})
    host = f.split('/')[1]
    report = f.split('/')[-1]
    print(f'{host}  {report}: passed={s.get(\"test-count-passed\",\"?\")}, failed={s.get(\"test-count-failed\",\"?\")}, total={s.get(\"test-count\",\"?\")}')
"
```

**Expected output after hardening**:

```
debian-target:  passed=261, failed=19, total=280
ubuntu-target:  passed=261, failed=19, total=280
```

### 7.3 Why are there still failures?

A perfect score (0 failures) is rarely the correct target. The remaining failures typically fall into one of three categories:

1. **Environmental exceptions** — e.g., a passwordless sudo rule needed for the ansible automation account itself
2. **Requires a reboot** — some kernel-level controls (e.g., module blacklisting) only take full effect after a reboot; reboots are skipped in this workshop
3. **Deliberate exclusions** — controls that conflict with the environment (e.g., stricter partition requirements that weren't set at install time)

The goal of compliance is not a perfect score — it is **justified, documented exceptions**. Every failed check that you keep should have a written reason for why it is acceptable in your environment.

### 7.4 OS comparison

| Area | Debian 12 | Ubuntu 22.04 |
|------|-----------|--------------|
| Firewall tool | nftables | ufw |
| MAC framework | AppArmor (optional) | AppArmor (enforced by default) |
| Logging | rsyslog | rsyslog + journald |
| Init system | systemd | systemd |
| CIS role | DEBIAN12-CIS | UBUNTU22-CIS |

CIS benchmarks are OS-specific — you cannot apply the Debian 12 role to Ubuntu. The control IDs, remediation steps, and affected file paths differ between distributions. This is exactly why ansible-lockdown maintains separate roles per OS version.

---

## 8. Idempotency Demo

### 8.1 Run the hardening playbook a second time

```bash
cd ~/AnsibleLockdownWorkshopCSCGR2026
ansible-playbook playbooks/harden.yml
```

Wait for it to complete and look at the play recap:

```
PLAY RECAP ************************************************************
debian-target : ok=182  changed=0   unreachable=0  failed=0
ubuntu-target : ok=176  changed=0   unreachable=0  failed=0
```

**`changed=0`** — Ansible checked every single control, confirmed the system is already in the desired state, and made no modifications.

This is **idempotency** in practice. You can run this playbook:
- Every time a new server is deployed
- On a schedule to detect and correct configuration drift
- In a CI/CD pipeline as part of image baking
- After any change that might have modified system config

In all cases: if the system is already compliant, nothing happens. If something drifted, it gets fixed automatically.

### 8.2 Run the audit a final time

```bash
ansible-playbook playbooks/audit.yml
```

The scores should be identical to the post-hardening audit from Section 7 — confirming that re-running the hardening did not introduce any regressions and that the compliance state is stable.

### 8.3 What this workshop covered

- **Ansible fundamentals** — agentless SSH-based automation, inventory, playbooks, roles, parallel execution
- **CIS benchmarks** — what they are, Level 1 vs Level 2, relationship to STIG
- **ansible-lockdown** — how to consume a community hardening role, configure it, and run it
- **Pre/post audit workflow** — use Goss to establish a baseline, harden, then measure improvement
- **Idempotency** — the same playbook is safe to run repeatedly and will self-correct drift

### 8.4 What to explore next

- **Level 2 hardening** — set `debian12cis_level2: true` in `group_vars/cis_level1.yml` (or move the host to `cis_level2`) and observe what additional controls are applied
- **Ansible Vault** — encrypting secrets (passwords, keys) inside playbooks and vars files
- **CI/CD integration** — trigger hardening automatically in GitHub Actions or GitLab CI when a new base image is built
- **Configuration drift detection** — run the audit playbook on a cron job; alert when the `failed` count increases
- **ansible-lockdown STIG roles** — [`UBUNTU22-STIG`](https://github.com/ansible-lockdown/UBUNTU22-STIG) for environments requiring DoD-level compliance

### 8.5 Resources

- [ansible-lockdown GitHub organization](https://github.com/ansible-lockdown)
- [Ansible Documentation](https://docs.ansible.com)
- [CIS Benchmarks — free PDF downloads](https://www.cisecurity.org/cis-benchmarks)
- [Goss — server testing tool](https://github.com/goss-org/goss)
- [Cyber Security Challenge Greece](https://cybersecuritychallenge.gr/)
