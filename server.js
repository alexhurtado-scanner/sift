import express from "express";
import Anthropic from "@anthropic-ai/sdk";
import { fileURLToPath } from "url";
import path from "path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = Number(process.env.PORT || 5173);
const apiKey = process.env.ANTHROPIC_API_KEY;
const client = apiKey ? new Anthropic({ apiKey }) : null;

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/complete", async (req, res) => {
  if (!client) {
    res.status(503).type("text/plain").send("ANTHROPIC_API_KEY not set");
    return;
  }
  const { prompt } = req.body || {};
  if (typeof prompt !== "string" || !prompt.trim()) {
    res.status(400).type("text/plain").send("missing prompt");
    return;
  }

  try {
    const response = await client.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 4096,
      cache_control: { type: "ephemeral" },
      system: [
        {
          type: "text",
          text: "You are a JSON-returning assistant for the Sift detection-engineering triage tool. Return ONLY a single JSON object — no markdown fences, no prose outside the JSON. Follow the schema given in the user message exactly.",
        },
      ],
      messages: [{ role: "user", content: prompt }],
    });

    const text = response.content
      .filter((b) => b.type === "text")
      .map((b) => b.text)
      .join("");

    res.json({ text });
  } catch (err) {
    const status = err instanceof Anthropic.APIError ? err.status : 500;
    res.status(status || 500).type("text/plain").send(err.message || String(err));
  }
});

app.listen(PORT, () => {
  console.log(`sift listening at http://localhost:${PORT}`);
  if (!client) {
    console.log("  (live verdict path disabled — set ANTHROPIC_API_KEY to enable)");
  }
});
