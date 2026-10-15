import type { TimelineItem } from "../api/types";
import { formatTime } from "../format";

/**
 * The actor's activity around an incident. Flagged events are highlighted
 * with the rules that fired; unflagged context events are shown dimmed.
 */
export function Timeline({ items }: { items: TimelineItem[] }) {
  return (
    <ol className="timeline">
      {items.map(({ event, flagged, detector_ids }) => (
        <li key={event.event_id} className={flagged ? "flagged" : "context"}>
          <time dateTime={event.timestamp}>{formatTime(event.timestamp)}</time>
          <div>
            <strong>{event.event_name}</strong> <span className="muted">({event.service})</span>
            {!event.success && (
              <span className="badge failed">failed: {event.error_code ?? "error"}</span>
            )}
            <div className="muted">
              {event.principal ?? "unknown actor"} from {event.source_address ?? "unknown source"}
            </div>
            {flagged && (
              <div className="chips">
                {detector_ids.map((id) => (
                  <span key={id} className="chip">
                    {id}
                  </span>
                ))}
              </div>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}
