# Secure Runtime Sandbox

A Rust-based secure runtime that launches applications under a controlled sandbox policy.

The runtime verifies the application identity using its path and SHA-256 hash, loads a JSON security policy, prepares a sandbox configuration, then launches the target application in a restricted child process.

## Features

* Application identity verification using path and SHA-256 hash
* JSON-based security policies
* Filesystem access control using Landlock
* Read/write/execute allowlists
* Resource limits:

  * CPU time
  * memory
  * maximum file size
  * maximum process count
* TCP network access control:

  * outgoing TCP connections by port
  * TCP bind/listen by port
* JSONL security logging
* Child-process sandbox enforcement using `pre_exec`

## Architecture

```text
secure-runtime parent process
    |
    |-- parse CLI arguments
    |-- load JSON policy
    |-- verify app path and hash
    |-- prepare SandboxConfig
    |-- log security events
    |
    |-- spawn child process
            |
            |-- apply resource limits
            |-- apply Landlock filesystem/network rules
            |-- execute target application
```

## Project Structure

```text
src/
  cli.rs        CLI argument validation
  policy.rs     JSON policy parsing and validation
  identity.rs   app path and SHA-256 verification
  hash.rs       SHA-256 calculation
  logger.rs     JSONL security logging
  sandbox.rs    sandbox configuration and enforcement
  runner.rs     child process execution
  engine.rs     policy decision logic

test_apps/      Rust source files for sandbox probes
bin/            compiled test binaries
policies/       JSON policies for each test
logs/           runtime security logs
sandbox/        test input/output folders
```

## Usage

```bash
cargo run -- --policy <policy-file> --app <app-path>
```

Example:

```bash
cargo run -- --policy policies/fs_probe.json --app ./bin/fs_test
```

## Demo Tests

### Filesystem access

```bash
cargo run -- --policy policies/fs_probe.json --app ./bin/fs_test
```

This test verifies:

* allowed read from `sandbox/input`
* denied read from forbidden system paths
* allowed write to `sandbox/output`
* denied write to read-only paths

### File size limit

```bash
cargo run -- --policy policies/file_limit_probe.json --app ./bin/file_limit_test
```

This test verifies that a process cannot create a file larger than the configured limit.

### CPU limit

```bash
cargo run -- --policy policies/cpu_limit_probe.json --app ./bin/cpu_limit_test
```

This test verifies that a CPU-intensive process is terminated when it exceeds its CPU time limit.

### Memory limit

```bash
cargo run -- --policy policies/memory_limit_probe.json --app ./bin/memory_limit_test
```

This test verifies that excessive memory allocation is blocked.

### Process limit

```bash
cargo run -- --policy policies/process_limit_probe.json --app ./bin/process_limit_test
```

This test verifies that the application cannot spawn more processes than allowed.

### Network connect deny

```bash
cargo run -- --policy policies/network_connect_deny.json --app ./bin/network_connect_test
```

This test verifies that outgoing TCP connections are blocked when no TCP connect ports are allowed.

### Network connect allow

```bash
cargo run -- --policy policies/network_connect_allow.json --app ./bin/network_connect_test
```

This test verifies that outgoing TCP connections to allowed ports can succeed.

### Network bind deny

```bash
cargo run -- --policy policies/network_bind_deny.json --app ./bin/network_bind_test
```

This test verifies that the application cannot bind/listen on TCP ports when no bind ports are allowed.

### Network bind allow

```bash
cargo run -- --policy policies/network_bind_allow.json --app ./bin/network_bind_test
```

This test verifies that binding to an allowed TCP port can succeed.

## Policy Example

```json
{
  "app_id": "fs_test",
  "app_path": "./bin/fs_test",
  "app_hash": "SHA256_HASH_HERE",
  "default_action": "deny",

  "filesystem": {
    "read_allow": [
      "./sandbox/input",
      "/lib",
      "/lib64",
      "/usr/lib",
      "/etc/ld.so.cache"
    ],
    "write_allow": [
      "./sandbox/output"
    ],
    "exec_allow": [
      "./bin/fs_test"
    ],
    "deny": [
      "./sandbox/denied",
      "/root",
      "/home/achraf/.ssh"
    ]
  },

  "resources": {
    "cpu_seconds": 5,
    "memory_mb": 128,
    "max_file_size_mb": 20,
    "max_processes": 32
  },

  "network": {
    "connect_tcp": [80, 443],
    "bind_tcp": []
  }
}
```

## Logs

Security events are written in JSONL format:

```text
logs/events.jsonl
```

Example event types:

* `cli_check`
* `policy_load`
* `identity_check`
* `sandbox_prepare`
* `resource_limits_configured`
* `network_policy_configured`
* `app_spawn_attempt`
* `app_exit`
* `resource_limit_hit`

## Current Limitations

* Network control is TCP-port based, not domain/IP based.
* Memory and process limit hits may be handled inside the application and may not always be visible to the parent runtime.
* Landlock rules are Linux-specific.
* The current version focuses on local process sandboxing, not full container isolation.
* The current demo probes are designed for testing the runtime, not for production workloads.

## Status

This version implements a functional V1 secure runtime with filesystem, resource, and TCP network controls.
