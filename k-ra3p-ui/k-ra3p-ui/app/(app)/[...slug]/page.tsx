import { notFound, redirect } from "next/navigation";
import { PAGES } from "@/lib/pages";

// Routes that now have real data-driven pages — do NOT fall through to static fake data.
// Next.js will route these to their own page.tsx before this catch-all is reached,
// but this list acts as an explicit guard.
const REAL_ROUTES = new Set([
  "threats/alerts",
  "threats/rules",
  "threats/blocked",
  "network/nodes",
  "network/traffic",
  "audit",
  "vulnerabilities",
  "reports",
  "settings/users",
  "settings/api-keys",
]);

const tone = (v: string) =>
  /^(critical|revoked|offline)$/.test(v)
    ? "sev-critical"
    : /^(high|medium|open|disabled)$/.test(v)
    ? "sev-high"
    : /^(low|active|online|deployed|verified|ready|fixed)$/.test(v)
    ? "sev-low"
    : "";

export default function Page({ params }: { params: { slug: string[] } }) {
  const slug = params.slug.join("/");

  // Guard: real pages should never fall through here, but be safe.
  if (REAL_ROUTES.has(slug)) redirect(`/${slug}`);

  const p = PAGES[slug];
  if (!p) notFound();

  return (
    <>
      <div className="page-head">
        <div>
          <h3>{p.title}</h3>
          <p className="b3 muted">{p.desc}</p>
        </div>
        <button className="btn btn-primary md">{p.action}</button>
      </div>
      <div className="grid4">
        {p.stats.map(([l, v]) => (
          <div key={l} className="card stat">
            <span className="b4 muted">{l}</span>
            <strong>{v}</strong>
          </div>
        ))}
      </div>
      <div className="card" style={{ overflowX: "auto" }}>
        <table>
          <thead>
            <tr>
              {p.cols.map((c) => (
                <th key={c}>{c}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {p.rows.map((r, i) => (
              <tr key={i}>
                {r.map((c, j) => (
                  <td key={j}>
                    {tone(c) ? (
                      <span className={`badge ${tone(c)}`}>{c}</span>
                    ) : (
                      c
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
