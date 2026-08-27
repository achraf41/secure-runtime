const capabilities = [
  ["SHA-256", "Executable identity verification"],
  ["Landlock", "Filesystem access isolation"],
  ["Seccomp", "System call filtering"],
  ["Namespaces", "Linux process isolation"],
  ["no_new_privs", "Privilege escalation prevention"],
  ["Capabilities", "Capability set dropping"],
  ["cgroup v2", "Resource enforcement"],
  ["Timeouts", "Wall-clock supervision"],
  ["Output limits", "Bounded process output"],
];

export function SecurityCapabilities() {
  return (
    <section className="card capabilities-card">
      <div className="capabilities-heading">
        <div><span className="eyebrow">Defense in depth</span><h2>Runtime Security Capabilities</h2></div>
        <p>Available enforcement mechanisms provided by secure-runtime. Actual use depends on the selected policy and host support.</p>
      </div>
      <div className="capability-grid">
        {capabilities.map(([name, description]) => (
          <div className="capability" key={name}>
            <span className="capability-check">✓</span>
            <div><strong>{name}</strong><small>{description}</small></div>
          </div>
        ))}
      </div>
    </section>
  );
}
