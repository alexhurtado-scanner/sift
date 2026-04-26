/* global React, ReactDOM */
const { useState, useEffect, useRef, useMemo } = React;

// Minimal YAML/SPL/KQL highlighter — keys, strings, comments
function highlight(code, lang) {
  if (!code) return "";
  let s = code
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  if (lang === "yaml") {
    s = s.replace(/^(\s*)([#].*)$/gm, '$1<span class="c">$2</span>');
    s = s.replace(/^(\s*)([a-zA-Z_][\w.|]*)(\s*:)/gm, '$1<span class="k">$2</span>$3');
    s = s.replace(/('([^']|\\')*')/g, '<span class="s">$1</span>');
  } else {
    // generic SPL/KQL/Scanner
    s = s.replace(/(\/\/.*)$/gm, '<span class="c">$1</span>');
    s = s.replace(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g, '<span class="s">$1</span>');
    s = s.replace(/\b(let|where|join|kind|on|with|within|project|extend|sort|asc|desc|union|stats|table|eval|case|isnotnull|mvfilter|mvcount|transaction|maxspan|startswith|endswith|matches|contains|in|and|or|not|by|index|sourcetype|EventCode|EventID)\b/g, '<span class="k">$1</span>');
    s = s.replace(/\b(\d+(?:\.\d+)?[smhdMY]?)\b/g, '<span class="n">$1</span>');
  }
  return s;
}

function CopyButton({ text, label = "Copy" }) {
  const [copied, setCopied] = useState(false);
  return React.createElement(
    "button",
    {
      className: "copy" + (copied ? " copied" : ""),
      onClick: () => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1400);
      },
    },
    copied ? "Copied ✓" : label
  );
}

function CodeBlock({ code, lang, label }) {
  return (
    <div className="code-block">
      <div className="toolbar">
        <span>{label || lang}</span>
        <CopyButton text={code} />
      </div>
      <pre dangerouslySetInnerHTML={{ __html: highlight(code, lang) }} />
    </div>
  );
}

function Stamp({ verdict }) {
  const subs = {
    SHIP: "Build the detection",
    SKIM: "Worth a glance",
    SKIP: "Reclaim the hour",
  };
  return (
    <div className="stamp" data-v={verdict} key={verdict}>
      <div className="label">{verdict}</div>
      <div className="sub">{subs[verdict]}</div>
    </div>
  );
}

function FetchingState({ url }) {
  const lines = [
    { delay: 0, html: '<span class="c">// sift v0.2 — verdict engine</span>' },
    { delay: 120, html: `<span class="k">$</span> fetch <span class="s">"${url}"</span>` },
    { delay: 380, html: '<span class="c">  → reading content...</span>' },
    { delay: 720, html: '<span class="c">  → applying rubric...</span>' },
    { delay: 1100, html: '<span class="c">  → checking for Sigma-shaped artifacts...</span>' },
    { delay: 1500, html: '<span class="c">  → scoring confidence...</span>' },
  ];
  const [shown, setShown] = useState(0);
  useEffect(() => {
    const timers = lines.map((l, i) =>
      setTimeout(() => setShown(s => Math.max(s, i + 1)), l.delay)
    );
    return () => timers.forEach(clearTimeout);
  }, []);
  return (
    <div className="fetching">
      <div className="scan" />
      <div className="lines">
        {lines.slice(0, shown).map((l, i) => (
          <span key={i} className="ln" dangerouslySetInnerHTML={{ __html: l.html }} />
        ))}
      </div>
    </div>
  );
}

window.SiftBits = { CopyButton, CodeBlock, Stamp, FetchingState, highlight };
