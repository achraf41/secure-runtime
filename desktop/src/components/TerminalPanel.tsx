import { useEffect, useRef } from "react";
import type { TerminalChunk } from "../types";

export function TerminalPanel({ chunks, onClear }: { chunks: TerminalChunk[]; onClear: () => void }) {
  const terminalRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const terminal = terminalRef.current;
    if (terminal) terminal.scrollTop = terminal.scrollHeight;
  }, [chunks]);

  return (
    <section className="card terminal-card">
      <div className="terminal-header">
        <div><span className="eyebrow">Live process stream</span><h2>Application Output</h2></div>
        <div className="terminal-actions">
          <span className="stream-key stdout-key">stdout</span>
          <span className="stream-key stderr-key">stderr</span>
          <button className="text-button" onClick={onClear} type="button">Clear Output</button>
        </div>
      </div>
      <div className="terminal" ref={terminalRef} role="log" aria-live="polite">
        {chunks.length === 0 ? (
          <div className="terminal-empty"><span>$</span> Output from the sandboxed process will appear here.</div>
        ) : chunks.map((chunk) => (
          <span className={"terminal-chunk " + chunk.stream} key={chunk.id}>{chunk.text}</span>
        ))}
      </div>
    </section>
  );
}
