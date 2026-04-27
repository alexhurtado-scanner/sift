/* global React, ReactDOM, SiftBits, TranslationPanel, useTweaks, TweaksPanel, TweakSection, TweakRadio, TweakToggle */
const { useState, useEffect, useRef, useMemo } = React;
const { Stamp, FetchingState, CodeBlock, CopyButton } = window.SiftBits;

const EXAMPLES = [
  {
    url: "https://securelist.com/tr/lotus-wiper/119472/",
    verdict: "SHIP",
    title: "LOTUS Wiper deep-dive",
    source: "securelist.com",
  },
  {
    url: "https://thedfirreport.com/2026/04/22/bissa-scanner-exposed-ai-assisted-mass-exploitation-and-credential-harvesting/",
    verdict: "SHIP",
    title: "BISSA: AI-assisted mass exploitation",
    source: "thedfirreport.com",
  },
  {
    url: "https://www.huntress.com/blog/nightmare-eclipse-intrusion",
    verdict: "SKIM",
    title: "Nightmare Eclipse: 72-hour breakdown",
    source: "huntress.com",
  },
];

// Practitioners who lent us their AI-slop red flags.
// Swap `avatar` for a real headshot / GH avatar URL, and `href` for the
// project / LinkedIn link. Use `platform: "GH"` or `"LI"`.
const CONTRIBUTORS = [
  {
    name: "TODO — credit me",
    handle: "@yourhandle",
    platform: "LI",
    href: "https://www.linkedin.com/in/yourhandle",
    avatar: null, // e.g. "https://github.com/yourhandle.png"
    filter: "Intel coming out of Panther is flop.",
  },
  {
    name: "TODO — practitioner",
    handle: "@yourhandle",
    platform: "GH",
    href: "https://github.com/yourhandle",
    avatar: null,
    filter: "If the IOCs are all formatted as bullet points and nothing else, walk away.",
  },
  {
    name: "TODO — practitioner",
    handle: "@yourhandle",
    platform: "GH",
    href: "https://github.com/yourhandle",
    avatar: null,
    filter: "No timestamps, no telemetry, no thanks.",
  },
];

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "headlineFont": "serif",
  "palette": "dispatch",
  "paperTexture": true,
  "crtScanlines": true
}/*EDITMODE-END*/;

function App() {
  const [tweaks, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [url, setUrl] = useState("");
  const [submittedUrl, setSubmittedUrl] = useState(null);
  const [verdict, setVerdict] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const inputRef = useRef(null);

  // Apply tweaks to root
  useEffect(() => {
    const root = document.documentElement;
    const fontMap = {
      serif: '"Fraunces", "Times New Roman", Georgia, serif',
      hand: '"Caveat", "Bradley Hand", cursive',
      mono: '"JetBrains Mono", monospace',
    };
    root.style.setProperty("--headline", fontMap[tweaks.headlineFont] || fontMap.serif);
    root.dataset.palette = tweaks.palette;
    root.style.setProperty("--paper-tex", tweaks.paperTexture ? 1 : 0);
    root.dataset.crt = tweaks.crtScanlines ? "on" : "off";
  }, [tweaks]);

  useEffect(() => {
    if (!loading) inputRef.current?.focus();
  }, [loading, submittedUrl]);

  const submit = async (eOrUrl) => {
    let overrideUrl = null;
    if (typeof eOrUrl === "string") {
      overrideUrl = eOrUrl;
    } else if (eOrUrl?.preventDefault) {
      eOrUrl.preventDefault();
    }
    const trimmed = (overrideUrl ?? url).trim();
    if (!trimmed) return;
    setSubmittedUrl(trimmed);
    setLoading(true);
    setErr(null);
    setVerdict(null);

    // Canned demo path
    if (window.SIFT_DEMOS[trimmed]) {
      // Slight artificial delay so the scan animation has presence
      setTimeout(() => {
        setVerdict(window.SIFT_DEMOS[trimmed]);
        setLoading(false);
      }, 1700);
      return;
    }

    // Live Claude path
    try {
      const prompt = `You are SIFT, a detection-engineering triage assistant for security defenders. You speak in the editorial voice of "Detection Dispatch": dry, opinionated, defender-to-defender, light snark, no fluff.

Fetch and read this URL: ${trimmed}

Apply the SIFT rubric and return a verdict:
- SHIP: primary research with named TTPs, IOCs, or enough technical specificity that a detection engineer could write a Sigma rule from it.
- SKIM: real content but vendor-blog/narrative-heavy with low IOC density. Worth 3 minutes; not the eng backlog.
- SKIP: AI-generated listicle, recap of someone else's work, marketing fluff, or paywalled/inaccessible.

If you cannot access the URL, return SKIM with reasoning that explicitly names the access issue.

Return ONLY a JSON object (no markdown, no prose outside the JSON), shape:
{
  "verdict": "SHIP" | "SKIM" | "SKIP",
  "source": "domain.com",
  "title": "article title as published",
  "publishedAt": "Mon DD, YYYY or null",
  "readTime": "X min read or null",
  "reasoning": "ONE sentence in the Detection Dispatch voice — dry, defender-to-defender, ~40 words max",
  "confidence": 0.0-1.0,
  "tags": ["short-kebab-tag", "short-kebab-tag", "short-kebab-tag"],

  // ONLY if verdict is SHIP, include these:
  "ttp": {"name": "...", "mitre": "Txxxx[/Txxxx.xxx]", "summary": "2-3 sentence kill chain step"},
  "sigma": "FULL valid Sigma rule as YAML — title/id/status/description/author/date/references/logsource/detection/falsepositives/level/tags",
  "telemetry": [{"source": "...", "events": ["..."], "fields": ["..."], "config": "any non-default ingest config required"}],
  "notes": ["FP source / volume / tuning / correlation notes — 3 items"],

  // ONLY if verdict is SKIM, include these:
  "skimSummary": ["3 bullet-point key takeaways from the article"],
  "skimVerdict": "ONE editorial sentence — why it's skim and not ship"
}`;
      const text = await window.claude.complete(prompt);
      const jsonStr = text.match(/\{[\s\S]*\}/)?.[0] || text;
      const parsed = JSON.parse(jsonStr);
      setVerdict(parsed);
    } catch (e) {
      setErr(String(e.message || e));
    } finally {
      setLoading(false);
    }
  };

  const reset = () => {
    setSubmittedUrl(null);
    setVerdict(null);
    setUrl("");
    setErr(null);
  };

  const useExample = (u) => {
    setUrl(u);
    submit(u);
  };

  // Pre-submit hero
  if (!submittedUrl) {
    return (
      <>
        <Header />
        <Hero onSubmit={submit} url={url} setUrl={setUrl} inputRef={inputRef} examples={EXAMPLES} useExample={useExample} />
        <Footer />
        <TweakUI tweaks={tweaks} setTweak={setTweak} />
      </>
    );
  }

  return (
    <>
      <Header />
      <ResetBar url={submittedUrl} onReset={reset} />
      {loading && <FetchingState url={submittedUrl} />}
      {err && (
        <div className="err">
          <strong>Verdict engine errored</strong> — {err}<br />
          The model may not have been able to fetch this URL. Try a different one or a canned example.
        </div>
      )}
      {verdict && <VerdictView verdict={verdict} url={submittedUrl} />}
      <Footer />
      <TweakUI tweaks={tweaks} setTweak={setTweak} />
    </>
  );
}

function Header() {
  const today = useMemo(() => {
    const d = new Date();
    return d.toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" }).toUpperCase();
  }, []);
  return (
    <>
      <div className="masthead">
        <div className="wm">
          <div className="logo">Sift.</div>
          <div className="tag">A Detection Dispatch joint</div>
        </div>
        <div className="meta">
          {today}<br/>
          <span className="dot">●</span> verdict engine online
        </div>
      </div>
      <div className="subhead">
        <span><i className="glyph"/>Vol. 0 · Issue 02</span>
        <span><i className="glyph"/>Triage for the over-tabbed</span>
        <span><i className="glyph"/>Built by defenders, for the next ten minutes of yours</span>
      </div>
    </>
  );
}

function Hero({ onSubmit, url, setUrl, inputRef, examples, useExample }) {
  return (
    <section className="hero">
      <h1 className="editorial">
        Paste a security URL.<br/>
        Get a <span className="underline"><em>verdict</em></span> on whether it's worth your tokens.
      </h1>
      <p className="lede">
        Fifteen tabs open before your first coffee, three of them likely AI-generated, and you can't tell which without ten minutes per artifact. Sift reads it for you and stamps SHIP, SKIM, or SKIP. If it ships, you walk away with the Sigma rule, the telemetry you'll need, and a translation for whatever your SIEM happens to be this fiscal year.
      </p>
      <form className="cli" onSubmit={onSubmit}>
        <span className="prompt">$</span>
        <input
          ref={inputRef}
          type="url"
          placeholder="paste a URL — vendor blog, threat report, vibes-based listicle…"
          value={url}
          onChange={e => setUrl(e.target.value)}
          autoFocus
        />
        <span className="hint"><kbd>↵</kbd>to run</span>
        <button type="submit" className="run-btn">Run Sift</button>
      </form>
      <div className="examples">
        {examples.map(ex => (
          <button key={ex.url} className="example" onClick={() => useExample(ex.url)}>
            <span className="ex-tag" data-v={ex.verdict}>{ex.verdict}</span>
            <div className="ex-title">{ex.title}</div>
            <div className="ex-source">{ex.source}</div>
            <div className="ex-corner">try me →</div>
          </button>
        ))}
      </div>
    </section>
  );
}

function ResetBar({ url, onReset }) {
  return (
    <div className="reset-bar">
      <span style={{ color: "var(--accent-red)", fontWeight: 700 }}>$</span>
      <span style={{ color: "var(--ink-faded)" }}>sift</span>
      <span className="url">{url}</span>
      <button className="new-btn" onClick={onReset}>← new URL</button>
    </div>
  );
}

function VerdictView({ verdict, url }) {
  const v = verdict.verdict;
  return (
    <div>
      <div className="verdict-card">
        <Stamp verdict={v} />
        <div className="source-line">
          <span className="domain">{verdict.source}</span>
          {verdict.publishedAt && <><span className="sep"/><span>{verdict.publishedAt}</span></>}
          {verdict.readTime && <><span className="sep"/><span>{verdict.readTime}</span></>}
        </div>
        <h2 className="article-title">{verdict.title}</h2>
        <p className="reasoning">{verdict.reasoning}</p>
        <div className="meta-row">
          <span className="conf">
            confidence
            <span className="conf-bar"><i style={{ width: `${Math.round((verdict.confidence || 0.5) * 100)}%` }}/></span>
            <span style={{ marginLeft: 6 }}>{Math.round((verdict.confidence || 0.5) * 100)}%</span>
          </span>
          {verdict.tags?.map(t => <span key={t} className="pill">{t}</span>)}
        </div>

        {v === "SKIM" && (verdict.skimSummary || verdict.skimVerdict) && (
          <div className="skim-detail">
            {verdict.skimSummary && (
              <>
                <h4>What you'd learn in 3 minutes</h4>
                <ul>
                  {verdict.skimSummary.map((s, i) => <li key={i}>{s}</li>)}
                </ul>
              </>
            )}
            {verdict.skimVerdict && (
              <div className="closing">{verdict.skimVerdict}</div>
            )}
          </div>
        )}
      </div>

      {v === "SHIP" && <ShipDetail verdict={verdict} url={url} />}
    </div>
  );
}

function ShipDetail({ verdict, url }) {
  return (
    <>
      {verdict.ttp && (
        <section className="section ttp-section">
          <div className="hdr"><div className="title"><span className="num">01</span>The TTP</div></div>
          <div className="body ttp">
            <div className="name">{verdict.ttp.name}</div>
            <span className="mitre">MITRE {verdict.ttp.mitre}</span>
            <p className="summary">{verdict.ttp.summary}</p>
          </div>
        </section>
      )}

      {verdict.sigma && (
        <section className="section">
          <div className="hdr"><div className="title"><span className="num">02</span>Sigma rule</div></div>
          <CodeBlock code={verdict.sigma} lang="yaml" label="sigma · yaml" />
        </section>
      )}

      {verdict.telemetry && verdict.telemetry.length > 0 && (
        <section className="section">
          <div className="hdr"><div className="title"><span className="num">03</span>Required telemetry</div></div>
          <div className="body">
            <div className="telemetry-list">
              {verdict.telemetry.map((t, i) => (
                <div className="telemetry-row" key={i}>
                  <div className="src">{t.source}</div>
                  {t.events && (
                    <div className="events"><b style={{ color: "var(--ink-faded)" }}>events: </b>
                      {t.events.map((e, j) => <span key={j}>{e}</span>)}
                    </div>
                  )}
                  {t.fields && (
                    <div className="fields"><b style={{ color: "var(--ink-faded)" }}>fields: </b>
                      {t.fields.map((e, j) => <span key={j}>{e}</span>)}
                    </div>
                  )}
                  {t.config && <div className="config">{t.config}</div>}
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {verdict.notes && verdict.notes.length > 0 && (
        <section className="section">
          <div className="hdr"><div className="title"><span className="num">04</span>Implementation notes</div></div>
          <div className="body">
            <ul className="notes-list">
              {verdict.notes.map((n, i) => <li key={i}>{n}</li>)}
            </ul>
          </div>
        </section>
      )}

      <section className="section" style={{ background: "transparent", border: 0 }}>
        <div className="hdr" style={{ background: "rgba(0,0,0,0.04)", border: "1.5px solid var(--ink)", borderBottom: 0 }}>
          <div className="title"><span className="num">05</span>Translate for your stack</div>
        </div>
        <window.TranslationPanel url={url} sigma={verdict.sigma} />
      </section>
    </>
  );
}

function Footer() {
  return (
    <>
      <DispatchBar />
      <Thanks />
      <div className="footer">
        <div className="credit">An <em>editorial</em> companion to Detection Dispatch · alex's version</div>
        <div>sift.dev · v0.2 · the verdict is yours</div>
      </div>
    </>
  );
}

function Thanks() {
  if (!CONTRIBUTORS || CONTRIBUTORS.length === 0) return null;
  return (
    <section className="thanks">
      <div className="thanks-hdr">
        <h3 className="thanks-title">Special thanks to the practitioners who lent us their <em>filter</em>.</h3>
        <p className="thanks-blurb">
          Their pattern-matching, our scorecard. The red flags below taught Sift what AI slop smells like.
        </p>
      </div>
      <div className="thanks-grid">
        {CONTRIBUTORS.map((c, i) => (
          <a
            key={i}
            className="thanks-card"
            href={c.href}
            target="_blank"
            rel="noreferrer"
          >
            {c.avatar ? (
              <img className="avatar" src={c.avatar} alt={c.name} loading="lazy" />
            ) : (
              <span className="avatar placeholder" aria-hidden="true">
                {(c.name || "?").trim().charAt(0).toUpperCase()}
              </span>
            )}
            <div className="meta">
              <div className="name">{c.name}</div>
              <div className="handle">
                <span className="platform">{c.platform}</span>
                {c.handle}
              </div>
              <div className="filter">{c.filter}</div>
            </div>
          </a>
        ))}
      </div>
    </section>
  );
}

function DispatchBar() {
  return (
    <section className="dispatch-bar">
      <div className="dispatch-art" role="img" aria-label="Detection Dispatch — alex's version cover art" />
      <div className="dispatch-copy">
        <div className="kicker">★ from the team behind</div>
        <h3 className="head">Detection Dispatch — <em>alex's version</em></h3>
        <p className="blurb">
          The weekly briefing that named this rubric. If Sift earned its keep today, you'll like the show.
        </p>
        <div className="listen-row">
          <span className="lbl">Listen on</span>
          <a href="https://open.spotify.com/show/detection-dispatch" target="_blank" rel="noreferrer">Spotify</a>
          <a href="https://podcasts.apple.com/podcast/detection-dispatch" target="_blank" rel="noreferrer">Apple Podcasts</a>
          <a href="https://youtube.com/@detection-dispatch" target="_blank" rel="noreferrer">YouTube</a>
        </div>
      </div>
    </section>
  );
}

function TweakUI({ tweaks, setTweak }) {
  return (
    <TweaksPanel>
      <TweakSection title="Type">
        <TweakRadio
          label="Headline font"
          value={tweaks.headlineFont}
          onChange={v => setTweak("headlineFont", v)}
          options={[
            { value: "serif", label: "Fraunces" },
            { value: "hand", label: "Caveat" },
            { value: "mono", label: "Mono" },
          ]}
        />
      </TweakSection>
      <TweakSection title="Palette">
        <TweakRadio
          label="Accent palette"
          value={tweaks.palette}
          onChange={v => setTweak("palette", v)}
          options={[
            { value: "dispatch", label: "Dispatch" },
            { value: "muted", label: "Muted" },
            { value: "contrast", label: "High" },
          ]}
        />
      </TweakSection>
      <TweakSection title="Texture">
        <TweakToggle
          label="Paper grain & ruled lines"
          value={tweaks.paperTexture}
          onChange={v => setTweak("paperTexture", v)}
        />
        <TweakToggle
          label="CRT scanlines"
          value={tweaks.crtScanlines}
          onChange={v => setTweak("crtScanlines", v)}
        />
      </TweakSection>
    </TweaksPanel>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
