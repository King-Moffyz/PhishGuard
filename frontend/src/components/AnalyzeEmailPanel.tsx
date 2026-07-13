import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { pollAnalysisResult, submitEmailForAnalysis } from "../hooks/useApi";
import ShapExplanationPanel from "./ShapExplanationPanel";
import type { AlertExplanation, AnalyzeResult, Severity } from "../types";
import { isAnalyzeResult } from "../types";

const DEFAULT_ACCOUNT_ID = import.meta.env.VITE_DEFAULT_ACCOUNT_ID || "";

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-950 text-red-300 border-red-800",
  high: "bg-orange-950 text-orange-300 border-orange-800",
  medium: "bg-amber-950 text-amber-300 border-amber-800",
  low: "bg-lime-950 text-lime-300 border-lime-800",
};

const PHISHING_EXAMPLE = {
  from: '"PayPal Security" <security@paypa1-verify.tk>',
  subject: "URGENT: Your account will be closed - Action Required",
  body:
    "Dear Customer,\n\nWe detected unusual sign-in activity on your account. Your account will be " +
    "closed within 24 hours unless you verify your identity immediately.\n\n" +
    "Click here to verify: http://paypa1-verify.tk/login?redirect=account\n\n" +
    "Please confirm your password and login credentials urgently to avoid suspension.\n\nSecurity Team",
};

const LEGITIMATE_EXAMPLE = {
  from: '"Dana from Acme HR" <dana.ross@acme.example>',
  subject: "Reminder: benefits enrollment closes Friday",
  body:
    "Hi team,\n\nJust a reminder that open enrollment for benefits closes this Friday at 5pm. " +
    "You can review your options in the HR portal at any time before then.\n\n" +
    "Reach out if you have questions.\n\nThanks,\nDana",
};

function buildRawMime(from: string, subject: string, body: string): string {
  // Extract the sender domain for consistent Authentication-Results and Message-ID
  const senderMatch = from.match(/@([^>]+)/);
  const senderDomain = senderMatch ? senderMatch[1] : "demo.local";
  const messageId = `<${Date.now()}.${Math.random().toString(16).slice(2)}@${senderDomain}>`;
  return [
    `From: ${from}`,
    `To: analyst@acme.example`,
    `Subject: ${subject}`,
    `Message-ID: ${messageId}`,
    `Date: ${new Date().toUTCString()}`,
    `Received: from mail.${senderDomain} (mail.${senderDomain} [198.51.100.1]) by mx.acme.example; ${new Date().toUTCString()}`,
    `Authentication-Results: mx.acme.example; spf=pass smtp.mailfrom=${senderDomain}; dkim=pass header.d=${senderDomain}; dmarc=pass header.from=${senderDomain}`,
    `Content-Type: text/plain; charset=utf-8`,
    ``,
    body,
  ].join("\n");
}

type Status = "idle" | "submitting" | "polling" | "done" | "error";

export default function AnalyzeEmailPanel({ onAnalyzed }: { onAnalyzed?: () => void }) {
  const [from, setFrom] = useState(PHISHING_EXAMPLE.from);
  const [subject, setSubject] = useState(PHISHING_EXAMPLE.subject);
  const [body, setBody] = useState(PHISHING_EXAMPLE.body);
  const [status, setStatus] = useState<Status>("idle");
  const [result, setResult] = useState<AnalyzeResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);
  const attemptsRef = useRef(0);

  useEffect(() => {
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, []);

  function loadExample(example: typeof PHISHING_EXAMPLE) {
    setFrom(example.from);
    setSubject(example.subject);
    setBody(example.body);
    setResult(null);
    setStatus("idle");
    setErrorMessage(null);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!DEFAULT_ACCOUNT_ID) {
      setErrorMessage("VITE_DEFAULT_ACCOUNT_ID is not configured — see .env.example.");
      setStatus("error");
      return;
    }

    setStatus("submitting");
    setErrorMessage(null);
    setResult(null);

    try {
      const rawMime = buildRawMime(from, subject, body);
      const accepted = await submitEmailForAnalysis(rawMime, DEFAULT_ACCOUNT_ID);
      setStatus("polling");
      attemptsRef.current = 0;

      pollRef.current = window.setInterval(async () => {
        attemptsRef.current += 1;
        try {
          const data = await pollAnalysisResult(accepted.task_id);
          if (isAnalyzeResult(data)) {
            if (pollRef.current) window.clearInterval(pollRef.current);
            setResult(data);
            setStatus("done");
            onAnalyzed?.();
          } else if (attemptsRef.current > 60) {
            if (pollRef.current) window.clearInterval(pollRef.current);
            setErrorMessage("Still processing after 90s — the worker may be cold-starting (first BERT load can take ~45s). Try again shortly.");
            setStatus("error");
          }
        } catch (err) {
          if (pollRef.current) window.clearInterval(pollRef.current);
          setErrorMessage("Failed to fetch analysis result.");
          setStatus("error");
        }
      }, 1500);
    } catch (err) {
      setErrorMessage("Failed to submit email for analysis.");
      setStatus("error");
    }
  }

  const explanationForPanel: AlertExplanation | null = result
    ? { alert_id: result.alert_id ?? result.event_id, shap_explanation: result.shap_explanation, nl_summary: result.nl_summary }
    : null;

  return (
    <div className="flex flex-col gap-4 rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-300">Analyze an Email</h3>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => loadExample(PHISHING_EXAMPLE)}
            className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700"
          >
            Load phishing example
          </button>
          <button
            type="button"
            onClick={() => loadExample(LEGITIMATE_EXAMPLE)}
            className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700"
          >
            Load legitimate example
          </button>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <div>
          <label className="mb-1 block text-xs font-medium text-slate-400">From</label>
          <input
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            className="w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
            required
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-slate-400">Subject</label>
          <input
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            className="w-full rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
            required
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-slate-400">Body</label>
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            rows={6}
            className="w-full resize-y rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm text-slate-200"
            required
          />
        </div>
        <button
          type="submit"
          disabled={status === "submitting" || status === "polling"}
          className="self-start rounded bg-sky-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-sky-600 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {status === "submitting" || status === "polling" ? "Analyzing…" : "Analyze Email"}
        </button>
      </form>

      {(status === "submitting" || status === "polling") && (
        <p className="text-sm text-slate-500">
          Running the email through the detection pipeline… this can take up to a minute on a cold worker start.
        </p>
      )}

      {status === "error" && errorMessage && (
        <div className="rounded border border-red-900 bg-red-950 px-3 py-2 text-sm text-red-300">{errorMessage}</div>
      )}

      {status === "done" && result && (
        <div className="flex flex-col gap-4 border-t border-slate-800 pt-4">
          <div className="flex flex-wrap items-center gap-3">
            <span className={clsx("rounded border px-2 py-0.5 text-xs font-semibold uppercase", SEVERITY_STYLES[result.severity])}>
              {result.severity}
            </span>
            <span className="text-sm text-slate-300">{result.category.replace(/_/g, " ")}</span>
            <span className="font-mono text-sm text-slate-400">{(result.meta_confidence_score * 100).toFixed(1)}% confidence</span>
            {result.alert_id && <span className="text-xs text-emerald-400">Alert created — see queue below</span>}
          </div>
          <ShapExplanationPanel explanation={explanationForPanel} />
        </div>
      )}
    </div>
  );
}
