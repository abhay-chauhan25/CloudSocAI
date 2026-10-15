// Display helpers. Times are always shown in UTC, as CloudTrail records them,
// so analysts comparing the dashboard with raw logs see the same values.

export function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return `${date.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

export function formatPoints(points: number): string {
  return points >= 0 ? `+${points}` : `${points}`;
}

/** "false_positive" -> "False positive" */
export function formatLabel(value: string): string {
  const words = value.replaceAll("_", " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}
