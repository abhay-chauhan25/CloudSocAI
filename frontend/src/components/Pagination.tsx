export function Pagination({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  if (total <= limit) return null;
  const first = offset + 1;
  const last = Math.min(offset + limit, total);
  return (
    <nav className="pagination" aria-label="Pagination">
      <button type="button" disabled={offset === 0} onClick={() => onChange(offset - limit)}>
        Previous
      </button>
      <span>
        {first}–{last} of {total}
      </span>
      <button type="button" disabled={last >= total} onClick={() => onChange(offset + limit)}>
        Next
      </button>
    </nav>
  );
}
