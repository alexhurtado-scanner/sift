/* global React, SiftBits */
const { useState, useEffect, useRef } = React;
const { CodeBlock, CopyButton } = window.SiftBits;

const TARGETS = [
  { id: "splunk", label: "Splunk", lang: "spl", live: true },
  { id: "sentinel", label: "Sentinel", lang: "kql", live: true },
  { id: "scanner", label: "Scanner", lang: "scanner", live: true },
  { id: "chronicle", label: "Chronicle", lang: "yara-l", live: false },
  { id: "elastic", label: "Elastic", lang: "esql", live: false },
  { id: "panther", label: "Panther", lang: "python", live: false },
];

function TranslationPanel({ url, sigma }) {
  // Persist platform in URL params per PRD
  const initial = useMemo(() => {
    try {
      const u = new URL(window.location.href);
      return u.searchParams.get("siem") || "splunk";
    } catch { return "splunk"; }
  }, []);
  const [active, setActive] = useState(initial);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => {
    try {
      const u = new URL(window.location.href);
      u.searchParams.set("siem", active);
      window.history.replaceState(null, "", u.toString());
    } catch {}
  }, [active]);

  useEffect(() => {
    setErr(null);
    const target = TARGETS.find(t => t.id === active);
    if (!target || !target.live) {
      setData(null);
      return;
    }
    // Try canned demo first
    const cannedKey = `${url}::${active}`;
    if (window.SIFT_TRANSLATIONS && window.SIFT_TRANSLATIONS[cannedKey]) {
      setData(window.SIFT_TRANSLATIONS[cannedKey]);
      return;
    }
    // Live LLM translation
    let cancelled = false;
    setLoading(true);
    setData(null);
    (async () => {
      try {
        const prompt = `You are a detection engineer. Translate this Sigma rule into a native query for ${target.label}.

Sigma rule:
\`\`\`yaml
${sigma}
\`\`\`

Return ONLY a JSON object (no markdown fences, no prose) with this exact shape:
{
  "query": "the native query as a single string with newlines preserved",
  "sources": [{"sigma": "<sigma logsource>", "platform": "<how to express that source on the target platform>"}],
  "fieldMaps": [{"sigma": "<sigma field>", "platform": "<target platform field>"}],
  "notes": ["short string", "short string", "short string"]
}`;
        const text = await window.claude.complete(prompt);
        const jsonStr = text.match(/\{[\s\S]*\}/)?.[0] || text;
        const parsed = JSON.parse(jsonStr);
        if (!cancelled) setData(parsed);
      } catch (e) {
        if (!cancelled) setErr(String(e.message || e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [active, url, sigma]);

  const target = TARGETS.find(t => t.id === active);

  return (
    <div className="translate">
      <div className="t-hdr">
        <div className="lbl">
          Translate for your <em>SIEM</em> or <em>data lake</em>
        </div>
        <div style={{ fontSize: 10, color: "var(--ink-faded)", letterSpacing: "0.15em" }}>
          ?siem={active}
        </div>
      </div>
      <div className="targets">
        {TARGETS.map(t => (
          <button
            key={t.id}
            className="target-btn"
            data-active={String(t.id === active)}
            data-stub={String(!t.live)}
            onClick={() => setActive(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div className="t-body">
        {!target.live && (
          <div className="t-stub">
            “Translation for {target.label} ships in v0.3.”
            <small>For now, paste the Sigma into your favorite converter.</small>
          </div>
        )}
        {target.live && loading && (
          <div className="t-stub">
            translating to {target.label}…
            <small>this takes a few seconds</small>
          </div>
        )}
        {target.live && err && (
          <div className="err">
            <strong>translation failed</strong> — {err}
          </div>
        )}
        {target.live && data && (
          <>
            <CodeBlock code={data.query} lang={target.lang} label={`${target.label} · query`} />
            {data.sources && data.sources.length > 0 && (
              <div className="src-map">
                <div className="map-hdr">Log sources mapped</div>
                {data.sources.map((s, i) => (
                  <div className="map-row" key={i}>
                    <div className="from">{s.sigma}</div>
                    <div className="arrow">→</div>
                    <div className="to">{s.platform}</div>
                  </div>
                ))}
              </div>
            )}
            {data.fieldMaps && data.fieldMaps.length > 0 && (
              <div className="field-map">
                <div className="map-hdr">Field name divergences</div>
                {data.fieldMaps.map((f, i) => (
                  <div className="map-row" key={i}>
                    <div className="from">{f.sigma}</div>
                    <div className="arrow">→</div>
                    <div className="to">{f.platform}</div>
                  </div>
                ))}
              </div>
            )}
            {data.notes && data.notes.length > 0 && (
              <div className="platform-notes">
                <h5>{target.label} notes</h5>
                <ul className="notes-list">
                  {data.notes.map((n, i) => <li key={i}>{n}</li>)}
                </ul>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

const { useMemo } = React;
window.TranslationPanel = TranslationPanel;
