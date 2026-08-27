# Secure Runtime

A Linux application sandbox written in Rust that executes untrusted applications under a policy-driven security boundary.

The runtime combines Linux kernel security mechanisms, process supervision, resource controls, executable identity verification, and runtime monitoring to reduce the privileges and resources available to a sandboxed application.

> **Status:** Active development / research prototype.  
> This project is intended for experimentation and learning around Linux sandboxing and secure runtime design. It should not yet be considered production-hardened.

---

## Overview

`secure-runtime` executes an application according to a JSON security policy.

Instead of directly launching the requested executable, the runtime:

1. Loads and validates the security policy.
2. Opens and verifies the application executable.
3. Verifies its SHA-256 identity.
4. Creates the required Linux isolation environment.
5. Applies filesystem, syscall, privilege, and resource restrictions.
6. Launches the application under process supervision.
7. Monitors execution, resource usage, timeout, and application output.
8. Performs controlled termination and cleanup.

The objective is to build a small secure execution environment inspired by container runtimes and application sandboxes while keeping the architecture understandable and explicitly policy-driven.

---

## Security Features

### Executable Identity Verification

The runtime verifies the application before execution using SHA-256.

To reduce TOCTOU risks, verification and execution operate on the same opened executable file descriptor.

Execution uses:

```text
execveat(..., AT_EMPTY_PATH)
````

instead of reopening the executable by pathname after verification.

This protects against an attacker replacing the executable between verification and execution.

---

### Filesystem Isolation — Landlock

Linux Landlock is used to restrict filesystem access.

Policies can define allowed paths for:

* reading
* writing
* execution

The application receives only the filesystem permissions explicitly granted by the policy.

---

### Syscall Filtering — Seccomp

Seccomp-BPF is used to restrict system calls available to the application.

Supported profiles include:

```text
none
baseline
strict
```

The baseline profile blocks dangerous operations such as:

```text
ptrace
mount
umount2
pivot_root
reboot
kexec_load
kexec_file_load
init_module
finit_module
delete_module
swapon
swapoff
```

Policies can also define additional denied syscalls.

---

## Linux Namespaces

The runtime supports multiple Linux namespaces:

* User namespace
* UTS namespace
* IPC namespace
* Network namespace
* Mount namespace
* PID namespace

These isolate different parts of the application's view of the host system.

### PID Namespace

When enabled, the sandbox creates a private PID namespace.

A dedicated PID 1 supervisor is responsible for:

* launching the target application
* reaping zombie processes
* handling orphan processes
* forwarding signals
* supervising application shutdown

---

## Mount Isolation

The runtime can create a private mount namespace.

### Private `/tmp`

The sandbox can mount an isolated `tmpfs` over:

```text
/tmp
```

so applications do not share the host temporary directory.

### Private `/proc`

When a PID namespace is enabled, the runtime mounts a private `/proc` corresponding to the sandbox PID namespace.

---

## Privilege Hardening

Before the target application executes, the runtime applies additional privilege restrictions.

### `no_new_privs`

The runtime enables:

```text
PR_SET_NO_NEW_PRIVS
```

preventing the process from gaining new privileges through mechanisms such as setuid binaries.

### Linux Capabilities

Linux capabilities are dropped before executing the sandboxed application.

This reduces access to privileged kernel operations even when other isolation mechanisms are present.

---

## Resource Limits

The runtime supports two complementary resource-control mechanisms.

### RLIMIT

Traditional Unix resource limits can restrict resources such as:

* CPU time
* file size
* memory-related resources
* process count

### cgroup v2

The runtime also supports Linux cgroup v2.

Current controls include:

* maximum memory
* maximum number of processes
* CPU percentage

Example:

```json
"resources": {
  "memory_mb": 2048,
  "max_processes": 256,

  "cgroup": {
    "enabled": true,
    "cpu_percent": 100
  }
}
```

---

## cgroup Runtime Statistics

After execution, the runtime can collect statistics from the sandbox cgroup, including:

* peak memory usage
* CPU usage
* user CPU time
* system CPU time
* CPU throttling
* peak process count
* OOM events
* OOM kill events

The sandbox cgroup is cleaned up after execution.

---

## Wall-Clock Timeout

Applications can be given a maximum execution duration:

```json
"timeout_seconds": 30
```

This differs from `RLIMIT_CPU`.

`RLIMIT_CPU` measures CPU consumption, while `timeout_seconds` limits real elapsed execution time.

When the timeout expires, the runtime performs controlled termination:

```text
SIGTERM
   ↓
grace period
   ↓
SIGKILL
```

if the application does not exit voluntarily.

---

## Process Supervision

Sandboxed applications are launched inside dedicated process groups.

The runtime handles:

* `SIGINT`
* `SIGTERM`
* `SIGHUP`

Signals received by the supervisor are forwarded to the sandboxed application process group.

The PID 1 supervisor also reaps child processes and prevents zombie accumulation.

---

## File Descriptor Hardening

Before execution, unnecessary inherited file descriptors are sanitized.

The runtime uses mechanisms such as:

```text
close_range(..., CLOSE_RANGE_CLOEXEC)
```

to prevent sensitive runtime descriptors from leaking into the sandboxed application.

The verified executable descriptor is deliberately preserved when required for FD-based execution and interpreter scripts.

---

## Environment Sanitization

The application does not automatically inherit the complete host environment.

Instead, the runtime creates a minimal environment containing only safe variables such as:

```text
PATH
HOME
LANG
TERM
```

Sensitive host variables such as credentials, tokens, dynamic-loader configuration, and SSH agent sockets are not automatically forwarded.

---

## Standard Input Hardening

The application can be prevented from reading directly from the runtime's terminal input.

`stdin` can be redirected to:

```text
/dev/null
```

to prevent unexpected interaction with the host terminal.

---

## stdout / stderr Mediation

Application output is not written directly to the host terminal.

The runtime creates separate pipes:

```text
application stdout ──> pipe ──┐
                              │
                              ├──> secure-runtime
                              │
application stderr ──> pipe ──┘
```

The host-side runtime monitors both streams using Linux `poll()`.

This allows the runtime to:

* capture output
* forward output
* count generated bytes
* detect excessive output
* enforce output limits

---

## Output Size Limits

Policies can restrict the combined amount of stdout and stderr generated by an application.

Example:

```json
"max_output_kb": 1024
```

The runtime converts this internally to bytes.

stdout and stderr share the same output budget:

```text
stdout bytes
     +
stderr bytes
     =
total application output
```

When the limit is exceeded:

1. The violation is detected by the output monitor.
2. Additional output is no longer forwarded normally.
3. The host sends a notification through an internal control pipe.
4. The launcher initiates controlled sandbox termination.
5. The runtime exits with a dedicated output-limit status.

---

## Internal Runtime Control Channel

The runtime uses an internal control pipe for communication between the host-side monitor and the sandbox launcher.

```text
Application
    │
    ├── stdout/stderr
    │        ↓
    │   Output Monitor
    │        │
    │        │ violation
    │        ↓
    │   Control Pipe
    │        │
    │        ↓
    └── Sandbox Launcher
             │
             ↓
        Process Supervisor
```

This allows host-side monitoring mechanisms to trigger sandbox termination without directly manipulating unknown application processes.

---

## Architecture

A simplified execution flow looks like:

```text
                  JSON Policy
                       │
                       ▼
                Policy Validation
                       │
                       ▼
             Sandbox Configuration
                       │
                       ▼
          Open + Verify Executable
               SHA-256 / FD
                       │
                       ▼
                  Host Runtime
                  /          \
                 /            \
        Output Monitor       Launcher
              │                 │
       stdout/stderr         Namespaces
              │                 │
       Control Channel       cgroup
              │                 │
              └─────────────► PID 1
                                │
                          Resource Limits
                                │
                            Landlock
                                │
                         no_new_privs
                                │
                        Drop Capabilities
                                │
                            Seccomp
                                │
                           execveat()
                                │
                                ▼
                           Application
```

---

## Example Policy

```json
{
  "policy_version": 1,
  "app_id": "example_app",
  "app_path": "/path/to/example_app",
  "app_hash": "SHA256_HASH",
  "default_action": "deny",

  "filesystem": {
    "read_allow": [
      "/usr",
      "/lib",
      "/lib64",
      "/etc",
      "/dev/null"
    ],
    "write_allow": [],
    "exec_allow": [
      "/usr/bin"
    ],
    "deny": []
  },

  "resources": {
    "timeout_seconds": 30,
    "max_output_kb": 1024,
    "memory_mb": 512,
    "max_processes": 64,

    "rlimit": {
      "enabled": true,
      "cpu_seconds": 20,
      "max_file_size_mb": 100
    },

    "cgroup": {
      "enabled": true,
      "cpu_percent": 50
    }
  },

  "network": null,

  "seccomp": {
    "profile": "baseline",
    "deny": []
  },

  "namespace": {
    "uts": {
      "enabled": true,
      "hostname": "sandbox"
    },

    "ipc": true,
    "network": false,
    "pid": true,

    "mount": {
      "enabled": true,
      "private_tmp": true,
      "tmp_size_mb": 64
    }
  }
}
```

---

## Building

Requirements:

* Linux
* Rust toolchain
* Kernel support for the security mechanisms being used

Clone the repository:

```bash
git clone https://github.com/achraf41/secure-runtime.git
cd secure-runtime
```

Build:

```bash
cargo build
```

Or:

```bash
cargo build --release
```

---

## Running

The runtime expects a policy and an application:

```bash
cargo run -- \
  --policy policies/example.json \
  --app /path/to/application
```

Application arguments can also be passed through the runtime when supported by the CLI.

Before running an application, calculate its SHA-256 hash:

```bash
sha256sum /path/to/application
```

and place the result in:

```json
"app_hash": "..."
```

---

## cgroup v2 Notes

cgroup enforcement requires access to a delegated writable cgroup hierarchy.

On a systemd user session, a delegated scope can be created with:

```bash
systemd-run --user --scope -p Delegate=yes bash
```

The runtime can then create sandbox-specific child cgroups under the delegated hierarchy.

---

## Security Model

The runtime follows a defense-in-depth approach.

No single isolation mechanism is considered sufficient.

Instead, several layers are combined:

```text
Executable identity
        +
Filesystem restrictions
        +
Syscall filtering
        +
Namespaces
        +
Resource limits
        +
cgroup v2
        +
Privilege reduction
        +
FD/environment sanitization
        +
Process supervision
        +
Runtime monitoring
```

A failure or weakness in one layer should therefore still encounter additional restrictions.

---

## Current Project Status

Implemented:

* [x] JSON security policies
* [x] SHA-256 application verification
* [x] TOCTOU-resistant FD-based execution
* [x] Landlock filesystem isolation
* [x] Seccomp syscall filtering
* [x] User namespace
* [x] UTS namespace
* [x] IPC namespace
* [x] Network namespace
* [x] Mount namespace
* [x] PID namespace
* [x] Private `/tmp`
* [x] Private `/proc`
* [x] PID 1 supervision
* [x] Zombie/orphan reaping
* [x] Signal forwarding
* [x] Process-group termination
* [x] `no_new_privs`
* [x] Linux capability dropping
* [x] RLIMIT resource controls
* [x] cgroup v2 resource controls
* [x] cgroup statistics
* [x] Wall-clock execution timeout
* [x] File-descriptor sanitization
* [x] Environment sanitization
* [x] stdin hardening
* [x] stdout/stderr capture
* [x] Output-size monitoring
* [x] Output-limit enforcement
* [x] Runtime control channel
* [x] JSONL security logging

---

## Future Work

Possible future improvements include:

* stronger policy schema and version management
* automated integration tests
* expanded seccomp profiles
* richer security-event logging
* improved cgroup delegation discovery
* event-driven supervisor loops
* improved networking policies
* additional audit and observability features
* fuzzing and adversarial sandbox testing
* formal threat-model documentation

---

## Disclaimer

This project is currently a research and educational secure-runtime implementation.

Although it uses real Linux kernel security mechanisms, it has not undergone the security review required for use as a production isolation boundary against fully malicious workloads.

---

## Author

**Achraf Snoussi**

Software Engineering & Cybersecurity student

GitHub: [@achraf41](https://github.com/achraf41)

```
```
