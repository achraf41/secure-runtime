export type UiStatus = "idle" | "running" | "finished" | "failed";
export type ExecutionOutcome = "exited" | "signaled" | "timedOut" | "outputLimitExceeded";

export interface RunStatusEvent { runId: string; status: "running"; }
export interface OutputEvent { runId: string; stream: "stdout" | "stderr"; text: string; }

export interface CgroupStats {
  memoryPeakBytes: number | null;
  cpuUsageUsec: number | null;
  cpuUserUsec: number | null;
  cpuSystemUsec: number | null;
  cpuNrThrottled: number | null;
  cpuThrottledUsec: number | null;
  pidsPeak: number | null;
  oomCount: number | null;
  oomKillCount: number | null;
}

export interface ExecutionResult {
  runId: string;
  status: "finished";
  appId: string;
  outcome: ExecutionOutcome;
  exitCode: number | null;
  terminatingSignal: number | null;
  timedOut: boolean;
  outputLimitExceeded: boolean;
  outputBytesObserved: number;
  outputLimitBytes: number | null;
  runtimeDurationMs: number;
  cgroupStats: CgroupStats | null;
}

export interface FinishedEvent extends ExecutionResult {}
export interface FailedEvent { runId: string; status: "failed"; error: string; }
export type RuntimeFinishedEvent = FinishedEvent | FailedEvent;
export interface TerminalChunk { id: number; stream: "stdout" | "stderr"; text: string; }

export interface PolicyViewResponse {
  policy: PolicyDto;
  rawJson: unknown;
  canonicalJson: string;
}

export interface ExecutableHashResult {
  path: string;
  hash: string;
  suggestedAppId: string;
}

export interface PolicyDto {
  policyVersion: number;
  appId: string;
  appPath: string;
  appHash: string;
  defaultAction: string;
  filesystem: FileSystemPolicyDto;
  resources: ResourcePolicyDto | null;
  network: NetworkPolicyDto | null;
  seccomp: SeccompPolicyDto | null;
  namespace: NamespacePolicyDto | null;
}

export interface FileSystemPolicyDto {
  readAllow: string[];
  writeAllow: string[];
  execAllow: string[];
  deny: string[];
}

export interface NetworkPolicyDto {
  connectTcp: number[] | null;
  bindTcp: number[] | null;
}

export interface SeccompPolicyDto {
  profile: "none" | "baseline" | "strict" | null;
  deny: string[] | null;
}

export interface NamespacePolicyDto {
  uts: UtsPolicyDto | null;
  ipc: boolean | null;
  network: boolean | null;
  pid: boolean | null;
  mount: MountPolicyDto | null;
}

export interface UtsPolicyDto {
  enabled: boolean | null;
  hostname: string | null;
}

export interface MountPolicyDto {
  enabled: boolean | null;
  privateTmp: boolean | null;
  tmpSizeMb: number | null;
}

export interface ResourcePolicyDto {
  timeoutSeconds: number | null;
  maxOutputKb: number | null;
  memoryMb: number | null;
  maxProcesses: number | null;
  rlimit: RlimitPolicyDto | null;
  cgroup: CgroupPolicyDto | null;
}

export interface RlimitPolicyDto {
  enabled: boolean | null;
  cpuSeconds: number | null;
  maxFileSizeMb: number | null;
}

export interface CgroupPolicyDto {
  enabled: boolean | null;
  cpuPercent: number | null;
}

export interface SecurityLogEntry {
  timestamp: string;
  appId: string;
  eventType: string;
  decision: string | null;
  reason: string | null;
  riskScore: number | null;
  memoryPeakBytes: number | null;
  cpuUsageUsec: number | null;
  cpuUserUsec: number | null;
  cpuSystemUsec: number | null;
  cpuNrThrottled: number | null;
  cpuThrottledUsec: number | null;
  pidsPeak: number | null;
  oomCount: number | null;
  oomKillCount: number | null;
}

export interface SecurityLogsResponse {
  entries: SecurityLogEntry[];
  malformedLines: number;
  validEntriesSeen: number;
  maxEntries: number;
  limited: boolean;
  sourcePath: string;
}
