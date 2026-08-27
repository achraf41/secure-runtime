import { open } from "@tauri-apps/plugin-dialog";
import { formatError } from "../utils/errors";

interface FileSelectorProps {
  title: string;
  description: string;
  path: string;
  placeholder: string;
  jsonOnly?: boolean;
  disabled?: boolean;
  onSelect: (path: string) => void;
  onError: (message: string) => void;
  actionLabel?: string;
  onAction?: () => void;
}

export function FileSelector(props: FileSelectorProps) {
  async function browse() {
    try {
      const selected = await open({
        multiple: false,
        directory: false,
        filters: props.jsonOnly ? [{ name: "JSON policy", extensions: ["json"] }] : undefined,
      });
      if (typeof selected === "string") props.onSelect(selected);
    } catch (error) {
      props.onError(formatError(error));
    }
  }

  return (
    <section className="card file-card">
      <div className="card-heading">
        <div className="section-icon" aria-hidden="true">{props.jsonOnly ? "◇" : "▣"}</div>
        <div><h2>{props.title}</h2><p>{props.description}</p></div>
      </div>
      <div className="file-row">
        <div className={"path-display " + (props.path ? "has-value" : "")} title={props.path}>
          {props.path || props.placeholder}
        </div>
        <button className="secondary-button" disabled={props.disabled} onClick={browse} type="button">
          Browse
        </button>
        {props.actionLabel && props.onAction && <button className="secondary-button" disabled={props.disabled || !props.path} onClick={props.onAction} type="button">{props.actionLabel}</button>}
      </div>
    </section>
  );
}
