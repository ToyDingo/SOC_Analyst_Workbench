"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { apiBase } from "@/lib/apiBase";

type JobStatus = "queued" | "running" | "done" | "failed";
type WorkflowStep = "upload" | "detect" | "respond";

type IngestJob = {
  job_id: string;
  upload_id: string;
  status: JobStatus;
  inserted_events: number | null;
  bad_lines: number | null;
  error: string | null;
  created_at?: any;
  updated_at?: any;
};

type Finding = {
  id: string;
  pattern_name: string;
  severity: "low" | "medium" | "high" | "critical" | string;
  confidence: number;
  title: string;
  summary: string;
  evidence: any;
  created_at: string | null;
};

type TimelineItem = {
  ts_start: string;
  ts_end: string;
  label: string;
  evidence_finding_ids: string[];
  evidence_event_ids: string[];
};

type Incident = {
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
  confirmed: boolean;
  security_outcomes: string[];
  affected_entities?: {
    user_emails?: string[];
    client_ips?: string[];
    dest_hosts?: string[];
    threat_categories?: string[];
  };
  evidence_finding_ids: string[];
  evidence_event_ids: string[];
  why: string[];
  recommended_actions: string[];
};

type SocReport = {
  summary: string;
  timeline?: TimelineItem[];
  incidents: Incident[];
  iocs: {
    domains: string[];
    urls: string[];
    ips: string[];
    users: string[];
  };
  gaps: string[];
  evidence_queries?: string[];
  recommended_actions?: string[];
};

type HistoryItem = {
  upload_id: string;
  filename?: string;
  created_at: string; // ISO
  soc_report?: SocReport | null; // <-- store full report
};

/** -------------------- SEM-ish (SolarWinds-like) Light Theme -------------------- */
const PAGE_BG = "#e9ecef"; // app canvas light gray
const SHELL_BG = "#2b2b2b"; // top nav dark
const PANEL_BG = "#f6f7f9"; // panel backdrop
const CARD_BG = "#ffffff"; // cards white
const CODE_BG = "#0b0b0b"; // code blocks near-black
const BORDER = "#cfd6de"; // subtle borders
const TEXT = "#1f2937"; // dark text
const MUTED = "#6b7280"; // muted gray
const ACCENT = "#1e88e5"; // SEM-ish blue accent
const ACCENT_DIM = "#e8f1ff"; // selected background tint
const BTN_BG = "#f3f4f6"; // button/input bg

function Pill({
  text,
  tone,
}: {
  text: string;
  tone?: "neutral" | "good" | "warn" | "bad" | "info";
}) {
  const bg =
    tone === "good"
      ? "#e9f7ef"
      : tone === "warn"
      ? "#fff4e5"
      : tone === "bad"
      ? "#fdecec"
      : tone === "info"
      ? "#e8f1ff"
      : "#f3f4f6";
  const fg =
    tone === "good"
      ? "#0f5132"
      : tone === "warn"
      ? "#7a4b00"
      : tone === "bad"
      ? "#7f1d1d"
      : tone === "info"
      ? "#0b4aa2"
      : "#374151";

  return (
    <span
      style={{
        background: bg,
        color: fg,
        padding: "3px 10px",
        borderRadius: 999,
        fontSize: 12,
        border: `1px solid ${BORDER}`,
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
      }}
    >
      {text}
    </span>
  );
}

function severityBadgeColor(sev: string) {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return { bg: "#b91c1c", fg: "#fff" };
  if (s === "high") return { bg: "#d97706", fg: "#fff" };
  if (s === "medium") return { bg: "#f59e0b", fg: "#111827" };
  if (s === "low") return { bg: "#16a34a", fg: "#fff" };
  return { bg: "#6b7280", fg: "#fff" };
}

function fmtPct(n: number) {
  const pct = Math.round((Number.isFinite(n) ? n : 0) * 100);
  return `${pct}%`;
}

function stepLabel(step: WorkflowStep) {
  if (step === "upload") return "Upload & Ingest";
  if (step === "detect") return "Detect";
  return "Generate Report";
}

export default function Page() {
  const router = useRouter();
  /* const API_BASE = useMemo(
    () => process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000",
    []
  ); */
  const API_BASE = useMemo(() => "/api", []);

  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);

  const [selectedStep, setSelectedStep] = useState<WorkflowStep>("upload");

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);

  const [uploadId, setUploadId] = useState<string | null>(null);
  const [ingestJobId, setIngestJobId] = useState<string | null>(null);

  const [uploadMsg, setUploadMsg] = useState("");
  const [ingestMsg, setIngestMsg] = useState("");
  const [ingest, setIngest] = useState<IngestJob | null>(null);

  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsMsg, setFindingsMsg] = useState("");
  const [findingsFilter, setFindingsFilter] = useState<string>("");

  const [socReport, setSocReport] = useState<SocReport | null>(null);
  const [socMsg, setSocMsg] = useState("");
  const [socGenerating, setSocGenerating] = useState(false);

  const [activeIncidentIdx, setActiveIncidentIdx] = useState<number>(0);

  // History (per-user)
  const [history, setHistory] = useState<HistoryItem[]>([]);

  const pollRef = useRef<number | null>(null);
  const clearPoll = () => {
    if (pollRef.current) window.clearInterval(pollRef.current);
    pollRef.current = null;
  };

  function historyKey(forEmail: string | null) {
    return forEmail ? `soc_history_${forEmail}` : "soc_history_anon";
  }

  function loadHistory(forEmail: string | null) {
    try {
      const raw = localStorage.getItem(historyKey(forEmail));
      const parsed = raw ? (JSON.parse(raw) as HistoryItem[]) : [];
      if (Array.isArray(parsed)) setHistory(parsed);
      else setHistory([]);
    } catch {
      setHistory([]);
    }
  }

  function saveHistory(forEmail: string | null, items: HistoryItem[]) {
    try {
      localStorage.setItem(historyKey(forEmail), JSON.stringify(items));
    } catch {
      // ignore
    }
  }

  function addHistoryItem(item: HistoryItem) {
    const next = [item, ...history].filter(
      (x, idx, arr) => arr.findIndex((y) => y.upload_id === x.upload_id) === idx
    );
    setHistory(next);
    saveHistory(email, next);
  }

  function updateHistoryItem(upload_id: string, patch: Partial<HistoryItem>) {
    const next = history.map((h) =>
      h.upload_id === upload_id ? { ...h, ...patch } : h
    );
    setHistory(next);
    saveHistory(email, next);
  }

  function removeHistoryItem(upload_id: string) {
    const next = history.filter((h) => h.upload_id !== upload_id);
    setHistory(next);
    saveHistory(email, next);
  }

  async function apiFetch(path: string, init?: RequestInit) {
    const headers: Record<string, string> = { ...(init?.headers as any) };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const res = await fetch(`${apiBase()}${path}`, { ...init, headers });

    // IMPORTANT: parse safely (agent endpoints sometimes return plain text on errors)
    const text = await res.text();
    let data: any = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { detail: text };
    }

    if (!res.ok)
      throw new Error(data?.detail ?? data?.error ?? `HTTP ${res.status}`);
    return data;
  }

  useEffect(() => {
    async function init() {
      const t = localStorage.getItem("access_token");
      if (!t) {
        router.push("/");
        return;
      }
      const res = await fetch(`${apiBase()}/auth/me`, {
        headers: { Authorization: `Bearer ${t}` },
      });
      if (!res.ok) {
        localStorage.removeItem("access_token");
        router.push("/");
        return;
      }
      const me = await res.json();
      setToken(t);
      setEmail(me.email ?? null);
      // Load per-user history after we know the email
      loadHistory(me.email ?? null);
    }
    init();
    return () => clearPoll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [API_BASE, router]);

  function logout() {
    localStorage.removeItem("access_token");
    router.push("/");
  }

  async function uploadFile() {
    if (!selectedFile || !token) return;

    setUploading(true);
    setUploadMsg("");
    setIngestMsg("");
    setUploadId(null);
    setIngestJobId(null);
    setIngest(null);
    setFindings([]);
    setFindingsMsg("");
    setSocReport(null);
    setSocMsg("");
    setSocGenerating(false);
    setActiveIncidentIdx(0);
    clearPoll();

    try {
      const form = new FormData();
      form.append("file", selectedFile);

      const res = await fetch(`${apiBase()}/upload`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: form,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.detail ?? `HTTP ${res.status}`);

      const uid = data?.id as string | undefined;
      const jid = data?.ingest_job_id as string | undefined;

      if (!uid) throw new Error("Upload succeeded but no upload id returned.");
      if (!jid) throw new Error("Upload succeeded but no ingest_job_id returned.");

      setUploadId(uid);
      setIngestJobId(jid);
      setUploadMsg(`Uploaded. upload_id=${uid}. Ingest queued. job_id=${jid}`);

      // record history (tied to login)
      addHistoryItem({
        upload_id: uid,
        filename: selectedFile?.name,
        created_at: new Date().toISOString(),
        soc_report: null,
      });

      // poll ingest
      pollRef.current = window.setInterval(async () => {
        try {
          const j = (await apiFetch(`/ingest/${jid}`)) as IngestJob;
          setIngest(j);

          if (j.status === "done") {
            setIngestMsg(
              `Ingest done. inserted=${j.inserted_events ?? 0}, bad_lines=${
                j.bad_lines ?? 0
              }`
            );
            clearPoll();
          } else if (j.status === "failed") {
            setIngestMsg(`Ingest failed: ${j.error ?? "unknown error"}`);
            clearPoll();
          } else {
            setIngestMsg(
              `Ingest ${j.status}... inserted=${j.inserted_events ?? 0}, bad_lines=${
                j.bad_lines ?? 0
              }`
            );
          }
        } catch (e: any) {
          setIngestMsg(
            `Polling ingest failed: ${e?.message ?? "unknown error"}`
          );
          clearPoll();
        }
      }, 2000);
    } catch (e: any) {
      setUploadMsg(`Upload failed: ${e?.message ?? "unknown error"}`);
    } finally {
      setUploading(false);
    }
  }

  async function runDetections() {
    if (!uploadId) return;
    setFindingsMsg("");
    try {
      await apiFetch(`/detect/${uploadId}`, { method: "POST" });
      setFindingsMsg("Detections queued. Refreshing findings in ~1s...");
      setTimeout(fetchFindings, 1000);
    } catch (e: any) {
      setFindingsMsg(
        `Could not run detections: ${e?.message ?? "unknown error"}`
      );
    }
  }

  async function fetchFindings() {
    if (!uploadId) return;
    setFindingsMsg("");
    try {
      const data = (await apiFetch(`/findings/${uploadId}`)) as Finding[];
      setFindings(data ?? []);
      setFindingsMsg(`Loaded ${data?.length ?? 0} findings.`);
    } catch (e: any) {
      setFindingsMsg(
        `Could not load findings: ${e?.message ?? "unknown error"}`
      );
    }
  }

  async function generateSocReport() {
    if (!uploadId) return;
    setSocMsg("");
    setSocReport(null);
    setSocGenerating(true);
    try {
      const rep = (await apiFetch(`/agent/report/${uploadId}`, {
        method: "POST",
      })) as SocReport;
      setSocReport(rep);
      updateHistoryItem(uploadId, { soc_report: rep }); // <-- persist full report to history
      setActiveIncidentIdx(0);
      setSocMsg("SOC report generated.");
    } catch (e: any) {
      setSocMsg(
        `Could not generate report: ${e?.message ?? "unknown error"}`
      );
    } finally {
      setSocGenerating(false);
    }
  }

  const ingestDone = ingest?.status === "done";
  const ingestFailed = ingest?.status === "failed";

  const severityTone = (sev: string) => {
    const s = (sev || "").toLowerCase();
    if (s === "critical" || s === "high") return "bad";
    if (s === "medium") return "warn";
    return "neutral";
  };

  const sortedFindings = useMemo(() => {
    const order: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
    };
    const filtered = findingsFilter.trim()
      ? findings.filter((f) => {
          const q = findingsFilter.trim().toLowerCase();
          return (
            (f.pattern_name ?? "").toLowerCase().includes(q) ||
            (f.title ?? "").toLowerCase().includes(q) ||
            (f.summary ?? "").toLowerCase().includes(q) ||
            (f.severity ?? "").toLowerCase().includes(q)
          );
        })
      : findings;

    return [...filtered].sort((a, b) => {
      const aScore = order[(a.severity || "").toLowerCase()] ?? 0;
      const bScore = order[(b.severity || "").toLowerCase()] ?? 0;
      if (bScore !== aScore) return bScore - aScore;
      return (b.confidence ?? 0) - (a.confidence ?? 0);
    });
  }, [findings, findingsFilter]);

  const activeIncident = socReport?.incidents?.[activeIncidentIdx] ?? null;

  function StepButton({
    step,
    disabled,
    subtitle,
    right,
  }: {
    step: WorkflowStep;
    disabled?: boolean;
    subtitle?: string;
    right?: React.ReactNode;
  }) {
    const selected = selectedStep === step;
    return (
      <button
        onClick={() => setSelectedStep(step)}
        disabled={disabled}
        style={{
          width: "100%",
          textAlign: "left",
          padding: "10px 10px",
          borderRadius: 12,
          border: selected ? `1px solid ${ACCENT}` : `1px solid ${BORDER}`,
          background: selected ? ACCENT_DIM : CARD_BG,
          color: TEXT,
          cursor: disabled ? "not-allowed" : "pointer",
          opacity: disabled ? 0.5 : 1,
          display: "grid",
          gridTemplateColumns: "1fr auto",
          gap: 8,
          alignItems: "center",
        }}
        title={disabled ? "Complete previous step(s) first" : ""}
      >
        <div>
          <div style={{ fontWeight: 800, letterSpacing: 0.2 }}>
            {stepLabel(step)}
          </div>
          {subtitle && (
            <div style={{ marginTop: 3, color: MUTED, fontSize: 12 }}>
              {subtitle}
            </div>
          )}
        </div>
        {right}
      </button>
    );
  }

  // Completion logic for "READY" labels (per your request)
  const step1Ready = !!uploadId && ingestDone;
  const step2Ready = !!uploadId && findings.length > 0;
  const step3Ready = !!uploadId && !!socReport && !socGenerating;

  return (
    <main
      style={{
        minHeight: "100vh",
        background: PAGE_BG,
        color: TEXT,
        fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
      }}
    >
      {/* Top bar */}
      <div
        style={{
          background: SHELL_BG,
          borderBottom: `1px solid ${BORDER}`,
          padding: "14px 18px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
        }}
      >
        <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
          <div style={{ fontWeight: 900, letterSpacing: 0.4, color: "#ffffff" }}>
            SOC Analyst Workbench
          </div>
          <div style={{ color: "#d1d5db", fontSize: 13 }}>
            Log Investigation Pipeline
          </div>
          {email && <Pill text={`User: ${email}`} tone="info" />}
        </div>

        <button
          onClick={logout}
          style={{
            padding: "8px 12px",
            cursor: "pointer",
            background: "#3a3a3a",
            color: "#ffffff",
            border: `1px solid #4b5563`,
            borderRadius: 10,
          }}
        >
          Logout
        </button>
      </div>

      {/* Main layout */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "260px 1fr 420px",
          gap: 12,
          padding: 12,
          maxWidth: 1500,
          margin: "0 auto",
        }}
      >
        {/* Left: Workflow / nav */}
        <aside
          style={{
            background: PANEL_BG,
            border: `1px solid ${BORDER}`,
            borderRadius: 14,
            padding: 12,
            height: "calc(100vh - 86px)",
            position: "sticky",
            top: 12,
            overflow: "auto",
          }}
        >
          <div style={{ fontWeight: 900, marginBottom: 10, letterSpacing: 0.2 }}>
            Workflow
          </div>

          <div style={{ display: "grid", gap: 10 }}>
            <StepButton
              step="upload"
              subtitle={uploadId ? `upload_id: ${uploadId}` : "Select a file to begin"}
              right={
                step1Ready ? (
                  <Pill text="READY" tone="good" />
                ) : uploadId ? (
                  <Pill text="STEP 1" tone="info" />
                ) : (
                  <Pill text="STEP 1" />
                )
              }
            />
            <StepButton
              step="detect"
              disabled={!uploadId || !ingestDone}
              subtitle={
                ingestDone
                  ? `Findings: ${findings.length}`
                  : ingestFailed
                  ? "Ingest failed"
                  : ingest
                  ? `Ingest: ${ingest.status}`
                  : "Waiting on ingest"
              }
              right={
                step2Ready ? (
                  <Pill text="READY" tone="good" />
                ) : uploadId ? (
                  <Pill text="STEP 2" tone={ingestDone ? "info" : "neutral"} />
                ) : (
                  <Pill text="STEP 2" tone="neutral" />
                )
              }
            />
            <StepButton
              step="respond"
              disabled={!uploadId || findings.length === 0}
              subtitle={
                socReport
                  ? "Report ready"
                  : socGenerating
                  ? "Generating report..."
                  : "Generate SOC report"
              }
              right={
                socGenerating ? (
                  <Pill text="RUNNING" tone="warn" />
                ) : step3Ready ? (
                  <Pill text="READY" tone="good" />
                ) : (
                  <Pill text="STEP 3" tone="info" />
                )
              }
            />
          </div>

          {/* History tab/function (tied to login) */}
          <div style={{ marginTop: 14, borderTop: `1px solid ${BORDER}`, paddingTop: 12 }}>
            <details>
              <summary style={{ cursor: "pointer", color: TEXT, fontWeight: 900 }}>
                History
                <span style={{ marginLeft: 8, color: MUTED, fontWeight: 600, fontSize: 12 }}>
                  ({history.length})
                </span>
              </summary>

              <div
                style={{
                  marginTop: 10,
                  display: "grid",
                  gap: 8,
                  width: "100%",
                  maxWidth: "100%",
                  overflow: "hidden",
                }}
              >
                {history.length === 0 ? (
                  <div style={{ color: MUTED, fontSize: 13 }}>
                    No history yet for this user. Upload a log to create entries.
                  </div>
                ) : (
                  history.map((h) => (
                    <button
                      key={h.upload_id}
                      onClick={() => {
                        setUploadId(h.upload_id);
                        setIngestJobId(null);
                        setIngest(null);
                        setIngestMsg("");
                        setUploadMsg(`Loaded from history. upload_id=${h.upload_id}`);
                        setFindings([]);
                        setFindingsMsg("Loaded from history. Refresh findings to continue.");
                        setSocReport(h.soc_report ?? null);
                        setSocMsg(h.soc_report ? "Loaded SOC report from history." : "");
                        setSocGenerating(false);
                        setActiveIncidentIdx(0);
                        clearPoll();
                        setSelectedStep(h.soc_report ? "respond" : "detect");
                      }}
                      style={{
                        background: CARD_BG,
                        border: `1px solid ${BORDER}`,
                        borderRadius: 12,
                        padding: 10,
                        textAlign: "left",
                        cursor: "pointer",
                        width: "100%",
                        maxWidth: "100%",
                        boxSizing: "border-box",
                        overflow: "hidden",
                        display: "block",
                      }}
                      title="Select to view this upload"
                    >
                      <div style={{ minWidth: 0 }}>
                        <div
                          style={{
                            fontWeight: 800,
                            fontSize: 13,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                          title={h.upload_id}
                        >
                          {h.upload_id}
                        </div>
                        <div style={{ marginTop: 4, color: MUTED, fontSize: 12 }}>
                          {h.filename ? h.filename : "—"} •{" "}
                          {new Date(h.created_at).toLocaleString()}
                          {h.soc_report ? " • report saved" : ""}
                        </div>
                      </div>
                    </button>
                  ))
                )}
              </div>
            </details>
          </div>

          <div style={{ marginTop: 14, borderTop: `1px solid ${BORDER}`, paddingTop: 12 }}>
            <div style={{ color: MUTED, fontSize: 12, marginBottom: 6 }}>Session</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {uploadId && <Pill text={`upload: ${uploadId.slice(0, 8)}…`} />}
              {ingestJobId && <Pill text={`ingest: ${ingestJobId.slice(0, 8)}…`} />}
              {ingest?.status && (
                <Pill
                  text={`ingest: ${ingest.status}`}
                  tone={ingestDone ? "good" : ingestFailed ? "bad" : "neutral"}
                />
              )}
            </div>
          </div>
        </aside>

        {/* Center: Content for selected workflow step */}
        <section
          style={{
            background: PANEL_BG,
            border: `1px solid ${BORDER}`,
            borderRadius: 14,
            padding: 12,
            height: "calc(100vh - 86px)",
            overflow: "hidden",
            display: "grid",
            gridTemplateRows: "auto 1fr",
            gap: 10,
          }}
        >
          {/* Header */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 10,
              paddingBottom: 8,
              borderBottom: `1px solid ${BORDER}`,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <div style={{ fontWeight: 900, letterSpacing: 0.2 }}>
                {stepLabel(selectedStep)}
              </div>
              {selectedStep === "upload" && <Pill text="Ingest pipeline" tone="info" />}
              {selectedStep === "detect" && <Pill text="Detection engine" tone="info" />}
              {selectedStep === "respond" && <Pill text="AI analyst" tone="info" />}
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              {selectedStep === "detect" && (
                <input
                  value={findingsFilter}
                  onChange={(e) => setFindingsFilter(e.target.value)}
                  placeholder="Filter findings (severity/title/pattern)..."
                  style={{
                    background: BTN_BG,
                    color: TEXT,
                    border: `1px solid ${BORDER}`,
                    borderRadius: 10,
                    padding: "9px 10px",
                    minWidth: 320,
                  }}
                />
              )}
            </div>
          </div>

          {/* Body */}
          <div style={{ overflow: "auto", paddingRight: 2 }}>
            {/* UPLOAD */}
            {selectedStep === "upload" && (
              <div style={{ display: "grid", gap: 12 }}>
                <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
                  <input
                    type="file"
                    onChange={(e) => setSelectedFile(e.target.files?.[0] ?? null)}
                    style={{
                      color: TEXT,
                      background: BTN_BG,
                      border: `1px solid ${BORDER}`,
                      borderRadius: 10,
                      padding: 8,
                      maxWidth: 520,
                    }}
                  />
                  <button
                    onClick={uploadFile}
                    disabled={!token || uploading || !selectedFile}
                    style={{
                      padding: "10px 12px",
                      cursor: "pointer",
                      background: BTN_BG,
                      color: TEXT,
                      border: `1px solid ${BORDER}`,
                      borderRadius: 10,
                    }}
                  >
                    {uploading ? "Uploading..." : "Upload"}
                  </button>
                  {uploadId && <Pill text={`upload_id: ${uploadId}`} tone="good" />}
                  {ingestJobId && <Pill text={`ingest_job_id: ${ingestJobId}`} />}
                </div>

                {uploadMsg && (
                  <div
                    style={{
                      background: CARD_BG,
                      border: `1px solid ${BORDER}`,
                      borderRadius: 12,
                      padding: 10,
                    }}
                  >
                    {uploadMsg}
                  </div>
                )}

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
                  <div style={{ padding: 12, border: `1px solid ${BORDER}`, borderRadius: 12, background: CARD_BG }}>
                    <div style={{ fontSize: 12, color: MUTED }}>ingest status</div>
                    <div style={{ marginTop: 6, fontWeight: 800 }}>{ingest?.status ?? "—"}</div>
                    {ingestMsg && <div style={{ marginTop: 6, color: MUTED, fontSize: 12 }}>{ingestMsg}</div>}
                  </div>
                  <div style={{ padding: 12, border: `1px solid ${BORDER}`, borderRadius: 12, background: CARD_BG }}>
                    <div style={{ fontSize: 12, color: MUTED }}>inserted events</div>
                    <div style={{ marginTop: 6, fontWeight: 800 }}>{ingest?.inserted_events ?? 0}</div>
                  </div>
                  <div style={{ padding: 12, border: `1px solid ${BORDER}`, borderRadius: 12, background: CARD_BG }}>
                    <div style={{ fontSize: 12, color: MUTED }}>bad lines</div>
                    <div style={{ marginTop: 6, fontWeight: 800 }}>{ingest?.bad_lines ?? 0}</div>
                  </div>
                </div>
              </div>
            )}

            {/* DETECT */}
            {selectedStep === "detect" && (
              <div style={{ display: "grid", gap: 12 }}>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
                  <button
                    onClick={runDetections}
                    disabled={!uploadId || !ingestDone}
                    style={{
                      padding: "10px 12px",
                      cursor: "pointer",
                      background: BTN_BG,
                      color: TEXT,
                      border: `1px solid ${BORDER}`,
                      borderRadius: 10,
                    }}
                    title={!ingestDone ? "Wait until ingest is done" : ""}
                  >
                    Run detections
                  </button>
                  <button
                    onClick={fetchFindings}
                    disabled={!uploadId}
                    style={{
                      padding: "10px 12px",
                      cursor: "pointer",
                      background: BTN_BG,
                      color: TEXT,
                      border: `1px solid ${BORDER}`,
                      borderRadius: 10,
                    }}
                  >
                    Refresh findings
                  </button>
                  <Pill text={`findings: ${findings.length}`} tone="info" />
                  {findingsMsg && <span style={{ color: MUTED, fontSize: 12 }}>{findingsMsg}</span>}
                </div>

                {sortedFindings.length === 0 ? (
                  <div style={{ color: MUTED }}>No findings yet.</div>
                ) : (
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr style={{ textAlign: "left", borderBottom: `1px solid ${BORDER}` }}>
                          <th style={{ padding: "8px 6px" }}>Severity</th>
                          <th style={{ padding: "8px 6px" }}>Pattern</th>
                          <th style={{ padding: "8px 6px" }}>Confidence</th>
                          <th style={{ padding: "8px 6px" }}>Title / Summary</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sortedFindings.map((f) => {
                          const sev = (f.severity || "").toLowerCase();
                          const rowBg =
                            sev === "critical"
                              ? "#fdecec"
                              : sev === "high"
                              ? "#fff4e5"
                              : sev === "medium"
                              ? "#fff7e0"
                              : CARD_BG;

                          return (
                            <tr
                              key={f.id}
                              style={{
                                borderBottom: `1px solid ${BORDER}`,
                                verticalAlign: "top",
                                background: rowBg,
                              }}
                            >
                              <td style={{ padding: "10px 6px" }}>
                                <Pill text={f.severity} tone={severityTone(f.severity) as any} />
                              </td>
                              <td style={{ padding: "10px 6px", fontFamily: "monospace", fontSize: 12, color: TEXT }}>
                                {f.pattern_name}
                              </td>
                              <td style={{ padding: "10px 6px", color: TEXT }}>
                                {Number(f.confidence).toFixed(2)}
                              </td>
                              <td style={{ padding: "10px 6px", color: TEXT }}>
                                <div style={{ fontWeight: 800 }}>{f.title}</div>
                                <div style={{ opacity: 0.95, marginTop: 4, color: TEXT }}>{f.summary}</div>
                                <details style={{ marginTop: 8 }}>
                                  <summary style={{ cursor: "pointer", color: MUTED }}>Evidence JSON</summary>
                                  <pre
                                    style={{
                                      background: CODE_BG,
                                      color: "#e5e7eb",
                                      padding: 12,
                                      borderRadius: 10,
                                      overflowX: "auto",
                                      border: `1px solid ${BORDER}`,
                                      marginTop: 8,
                                    }}
                                  >
                                    {JSON.stringify(f.evidence, null, 2)}
                                  </pre>
                                </details>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* RESPOND */}
            {selectedStep === "respond" && (
              <div style={{ display: "grid", gap: 12 }}>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
                  <button
                    onClick={generateSocReport}
                    disabled={!uploadId || findings.length === 0 || socGenerating}
                    style={{
                      padding: "10px 12px",
                      cursor: socGenerating ? "not-allowed" : "pointer",
                      background: socGenerating ? ACCENT_DIM : BTN_BG,
                      color: TEXT,
                      border: `1px solid ${BORDER}`,
                      borderRadius: 10,
                    }}
                    title={findings.length === 0 ? "Run detections first (so the agent has findings)" : ""}
                  >
                    {socGenerating ? "Generating report..." : "Generate SOC report"}
                  </button>

                  {socGenerating && <Pill text="Please wait — AI is analyzing findings…" tone="warn" />}
                  {socMsg && !socGenerating && <span style={{ color: MUTED, fontSize: 12 }}>{socMsg}</span>}

                  {socReport && (
                    <button
                      onClick={() => navigator.clipboard.writeText(JSON.stringify(socReport, null, 2))}
                      style={{
                        padding: "10px 12px",
                        cursor: "pointer",
                        background: BTN_BG,
                        color: TEXT,
                        border: `1px solid ${BORDER}`,
                        borderRadius: 10,
                      }}
                      title="Copy full SOC report JSON to clipboard"
                    >
                      Copy JSON
                    </button>
                  )}
                </div>

                {!socReport && !socGenerating && (
                  <div style={{ color: MUTED }}>
                    Generate a report to populate the Incident details pane and the IOC/Gaps pane.
                  </div>
                )}

                {socReport && (
                  <div style={{ display: "grid", gap: 12 }}>
                    <div style={{ padding: 12, border: `1px solid ${BORDER}`, borderRadius: 12, background: CARD_BG }}>
                      <div style={{ fontWeight: 900, marginBottom: 6 }}>Executive Summary</div>
                      <div style={{ lineHeight: 1.55, color: TEXT, fontSize: 14 }}>{socReport.summary}</div>
                    </div>

                    <div style={{ padding: 12, border: `1px solid ${BORDER}`, borderRadius: 12, background: CARD_BG }}>
                      <div style={{ fontWeight: 900, marginBottom: 10 }}>Timeline</div>
                      {(socReport.timeline ?? []).length === 0 ? (
                        <div style={{ color: MUTED }}>No timeline items returned.</div>
                      ) : (
                        <div style={{ overflowX: "auto" }}>
                          <table style={{ width: "100%", borderCollapse: "collapse" }}>
                            <thead>
                              <tr style={{ textAlign: "left", borderBottom: `1px solid ${BORDER}` }}>
                                <th style={{ padding: "8px 6px" }}>Start</th>
                                <th style={{ padding: "8px 6px" }}>End</th>
                                <th style={{ padding: "8px 6px" }}>Label</th>
                                <th style={{ padding: "8px 6px" }}>Evidence</th>
                              </tr>
                            </thead>
                            <tbody>
                              {(socReport.timeline ?? []).map((t, idx) => (
                                <tr
                                  key={idx}
                                  style={{
                                    borderBottom: `1px solid ${BORDER}`,
                                    verticalAlign: "top",
                                    background: "#f6f7f9",
                                  }}
                                >
                                  <td style={{ padding: "8px 6px", fontSize: 12, fontFamily: "monospace", color: TEXT }}>
                                    {t.ts_start}
                                  </td>
                                  <td style={{ padding: "8px 6px", fontSize: 12, fontFamily: "monospace", color: TEXT }}>
                                    {t.ts_end}
                                  </td>
                                  <td style={{ padding: "8px 6px", color: TEXT }}>{t.label}</td>
                                  <td style={{ padding: "8px 6px" }}>
                                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                                      {(t.evidence_finding_ids ?? []).map((id) => (
                                        <span
                                          key={id}
                                          style={{
                                            background: BTN_BG,
                                            color: TEXT,
                                            padding: "2px 8px",
                                            borderRadius: 999,
                                            fontSize: 11,
                                            fontFamily: "monospace",
                                            border: `1px solid ${BORDER}`,
                                          }}
                                        >
                                          {id}
                                        </span>
                                      ))}
                                      {(t.evidence_event_ids ?? []).map((id) => (
                                        <span
                                          key={id}
                                          style={{
                                            background: ACCENT_DIM,
                                            color: "#0b4aa2",
                                            padding: "2px 8px",
                                            borderRadius: 999,
                                            fontSize: 11,
                                            fontFamily: "monospace",
                                            border: `1px solid ${BORDER}`,
                                          }}
                                        >
                                          evt:{id}
                                        </span>
                                      ))}
                                      {(t.evidence_finding_ids ?? []).length === 0 &&
                                        (t.evidence_event_ids ?? []).length === 0 && (
                                          <span style={{ color: MUTED }}>—</span>
                                        )}
                                    </div>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </section>

        {/* Right: Findings/Incidents detail panes */}
        <aside
          style={{
            background: PANEL_BG,
            border: `1px solid ${BORDER}`,
            borderRadius: 14,
            padding: 12,
            height: "calc(100vh - 86px)",
            position: "sticky",
            top: 12,
            overflow: "hidden",
            display: "grid",
            gridTemplateRows: "auto auto 1fr",
            gap: 10,
          }}
        >
          {/* Quick status */}
          <div
            style={{
              background: CARD_BG,
              border: `1px solid ${BORDER}`,
              borderRadius: 12,
              padding: 10,
              display: "flex",
              flexWrap: "wrap",
              gap: 8,
              alignItems: "center",
              justifyContent: "space-between",
            }}
          >
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
              <Pill text={`Findings: ${findings.length}`} tone="info" />
              {socGenerating && <Pill text="SOC report running…" tone="warn" />}
              {socReport && !socGenerating && <Pill text="SOC report ready" tone="good" />}
            </div>
            <div style={{ color: MUTED, fontSize: 12 }}>
              {uploadId ? `upload ${uploadId.slice(0, 8)}…` : "no upload"}
            </div>
          </div>

          {/* Incident list */}
          <div
            style={{
              background: CARD_BG,
              border: `1px solid ${BORDER}`,
              borderRadius: 12,
              padding: 10,
            }}
          >
            <div style={{ fontWeight: 900, marginBottom: 8 }}>Incidents</div>
            {!socReport || (socReport.incidents ?? []).length === 0 ? (
              <div style={{ color: MUTED, fontSize: 13 }}>
                No incident objects yet. Generate the SOC report to populate incidents.
              </div>
            ) : (
              <div style={{ display: "grid", gap: 8 }}>
                {(socReport.incidents ?? []).map((inc, idx) => {
                  const c = severityBadgeColor(inc.severity);
                  const active = idx === activeIncidentIdx;
                  return (
                    <button
                      key={idx}
                      onClick={() => setActiveIncidentIdx(idx)}
                      style={{
                        width: "100%",
                        textAlign: "left",
                        padding: "10px 10px",
                        borderRadius: 12,
                        border: active ? `1px solid ${ACCENT}` : `1px solid ${BORDER}`,
                        background: active ? ACCENT_DIM : "#f6f7f9",
                        color: TEXT,
                        cursor: "pointer",
                        display: "grid",
                        gridTemplateColumns: "1fr auto",
                        gap: 10,
                        alignItems: "center",
                      }}
                    >
                      <div style={{ minWidth: 0 }}>
                        <div
                          style={{
                            fontWeight: 800,
                            fontSize: 13,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                          title={inc.title}
                        >
                          {inc.title}
                        </div>
                        <div style={{ marginTop: 4, display: "flex", gap: 6, flexWrap: "wrap" }}>
                          <span
                            style={{
                              background: c.bg,
                              color: c.fg,
                              padding: "2px 8px",
                              borderRadius: 999,
                              fontSize: 11,
                              border: `1px solid ${BORDER}`,
                            }}
                          >
                            {inc.severity.toUpperCase()}
                          </span>
                          <span
                            style={{
                              background: BTN_BG,
                              color: TEXT,
                              padding: "2px 8px",
                              borderRadius: 999,
                              fontSize: 11,
                              border: `1px solid ${BORDER}`,
                            }}
                          >
                            Conf: {fmtPct(inc.confidence)}
                          </span>
                          <span
                            style={{
                              background: BTN_BG,
                              color: TEXT,
                              padding: "2px 8px",
                              borderRadius: 999,
                              fontSize: 11,
                              border: `1px solid ${BORDER}`,
                            }}
                          >
                            {inc.confirmed ? "CONFIRMED" : "HYPOTHESIS"}
                          </span>
                        </div>
                      </div>
                      <span style={{ color: MUTED, fontSize: 12 }}>{active ? "▶" : ""}</span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Incident details (scrollable + slightly narrower text) */}
          <div
            style={{
              background: CARD_BG,
              border: `1px solid ${BORDER}`,
              borderRadius: 12,
              padding: 10,
              overflow: "hidden",
              display: "grid",
              gridTemplateRows: "auto 1fr",
              gap: 8,
              minHeight: 0,
            }}
          >
            <div style={{ fontWeight: 900 }}>Incident details</div>

            <div
              style={{
                overflowY: "auto",
                minHeight: 0,
                maxHeight: "100%",
                paddingRight: 6,
              }}
            >
              {!activeIncident ? (
                <div style={{ color: MUTED, fontSize: 13 }}>
                  Generate a SOC report and pick an incident to view details.
                </div>
              ) : (
                <div
                  style={{
                    display: "grid",
                    gap: 10,
                    fontSize: 13,
                    lineHeight: 1.45,
                    maxWidth: "100%",
                  }}
                >
                  {/* Security outcomes */}
                  <div>
                    <div style={{ color: MUTED, fontSize: 12, marginBottom: 6 }}>
                      Security outcomes
                    </div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {(activeIncident.security_outcomes ?? []).map((o) => (
                        <span
                          key={o}
                          style={{
                            background: ACCENT_DIM,
                            color: "#0b4aa2",
                            padding: "2px 8px",
                            borderRadius: 999,
                            fontSize: 11,
                            border: `1px solid ${BORDER}`,
                          }}
                        >
                          {o}
                        </span>
                      ))}
                      {(activeIncident.security_outcomes ?? []).length === 0 && (
                        <span style={{ color: MUTED }}>—</span>
                      )}
                    </div>
                  </div>

                  {/* Affected entities */}
                  <div>
                    <div style={{ color: MUTED, fontSize: 12, marginBottom: 6 }}>
                      Affected entities
                    </div>
                    <div style={{ display: "grid", gap: 8 }}>
                      {[
                        ["Users", activeIncident.affected_entities?.user_emails ?? []],
                        ["Client IPs", activeIncident.affected_entities?.client_ips ?? []],
                        ["Dest hosts", activeIncident.affected_entities?.dest_hosts ?? []],
                        ["Threat categories", activeIncident.affected_entities?.threat_categories ?? []],
                      ].map(([label, arr]: any) => (
                        <div
                          key={label}
                          style={{
                            border: `1px solid ${BORDER}`,
                            borderRadius: 12,
                            padding: 8,
                            background: "#f6f7f9",
                          }}
                        >
                          <div style={{ color: MUTED, fontSize: 12 }}>{label}</div>
                          <div
                            style={{
                              marginTop: 6,
                              display: "flex",
                              gap: 6,
                              flexWrap: "wrap",
                              maxWidth: "100%",
                            }}
                          >
                            {(arr as string[]).length === 0 ? (
                              <span style={{ color: MUTED }}>—</span>
                            ) : (
                              (arr as string[]).map((x) => (
                                <span
                                  key={x}
                                  style={{
                                    background: BTN_BG,
                                    color: TEXT,
                                    padding: "2px 8px",
                                    borderRadius: 999,
                                    fontSize: 11,
                                    border: `1px solid ${BORDER}`,
                                    fontFamily:
                                      label === "Threat categories"
                                        ? "inherit"
                                        : "ui-monospace, SFMono-Regular, Menlo, monospace",
                                    overflowWrap: "anywhere",
                                    wordBreak: "break-word",
                                    maxWidth: "100%",
                                  }}
                                >
                                  {x}
                                </span>
                              ))
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Why */}
                  <div>
                    <div style={{ color: MUTED, fontSize: 12, marginBottom: 6 }}>Why</div>
                    <ul
                      style={{
                        marginTop: 0,
                        marginBottom: 0,
                        paddingLeft: 18,
                        maxWidth: "100%",
                        overflowWrap: "anywhere",
                      }}
                    >
                      {(activeIncident.why ?? []).map((w, i) => (
                        <li key={i} style={{ marginBottom: 6 }}>
                          {w}
                        </li>
                      ))}
                      {(activeIncident.why ?? []).length === 0 && (
                        <li style={{ color: MUTED }}>—</li>
                      )}
                    </ul>
                  </div>

                  {/* Recommended actions */}
                  <div>
                    <div style={{ color: MUTED, fontSize: 12, marginBottom: 6 }}>
                      Recommended actions
                    </div>
                    <ol
                      style={{
                        marginTop: 0,
                        marginBottom: 0,
                        paddingLeft: 18,
                        maxWidth: "100%",
                        overflowWrap: "anywhere",
                      }}
                    >
                      {(activeIncident.recommended_actions ?? []).map((a, i) => (
                        <li key={i} style={{ marginBottom: 6 }}>
                          {a}
                        </li>
                      ))}
                      {(activeIncident.recommended_actions ?? []).length === 0 && (
                        <li style={{ color: MUTED }}>—</li>
                      )}
                    </ol>
                  </div>

                  {/* Evidence IDs */}
                  <details>
                    <summary style={{ cursor: "pointer", color: MUTED }}>Evidence IDs</summary>
                    <div style={{ marginTop: 8, display: "grid", gap: 10 }}>
                      <div>
                        <div style={{ color: MUTED, fontSize: 12 }}>Finding IDs</div>
                        <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                          {(activeIncident.evidence_finding_ids ?? []).map((id) => (
                            <span
                              key={id}
                              style={{
                                background: BTN_BG,
                                color: TEXT,
                                padding: "2px 8px",
                                borderRadius: 999,
                                fontSize: 11,
                                border: `1px solid ${BORDER}`,
                                fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
                                overflowWrap: "anywhere",
                                wordBreak: "break-word",
                              }}
                            >
                              {id}
                            </span>
                          ))}
                          {(activeIncident.evidence_finding_ids ?? []).length === 0 && (
                            <span style={{ color: MUTED }}>—</span>
                          )}
                        </div>
                      </div>

                      <div>
                        <div style={{ color: MUTED, fontSize: 12 }}>Event IDs</div>
                        <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                          {(activeIncident.evidence_event_ids ?? []).map((id) => (
                            <span
                              key={id}
                              style={{
                                background: ACCENT_DIM,
                                color: "#0b4aa2",
                                padding: "2px 8px",
                                borderRadius: 999,
                                fontSize: 11,
                                border: `1px solid ${BORDER}`,
                                fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
                                overflowWrap: "anywhere",
                                wordBreak: "break-word",
                              }}
                            >
                              {id}
                            </span>
                          ))}
                          {(activeIncident.evidence_event_ids ?? []).length === 0 && (
                            <span style={{ color: MUTED }}>None returned</span>
                          )}
                        </div>
                      </div>
                    </div>
                  </details>

                  {/* IOC/Gaps quick peek */}
                  {socReport && (
                    <details>
                      <summary style={{ cursor: "pointer", color: MUTED }}>IOCs / Gaps</summary>
                      <div style={{ marginTop: 10, display: "grid", gap: 10 }}>
                        <div>
                          <div style={{ color: MUTED, fontSize: 12 }}>IOCs</div>
                          <pre
                            style={{
                              background: CODE_BG,
                              color: "#e5e7eb",
                              padding: 10,
                              borderRadius: 10,
                              overflowX: "auto",
                              border: `1px solid ${BORDER}`,
                              marginTop: 6,
                              fontSize: 12,
                            }}
                          >
                            {JSON.stringify(socReport.iocs ?? {}, null, 2)}
                          </pre>
                        </div>
                        <div>
                          <div style={{ color: MUTED, fontSize: 12 }}>Gaps</div>
                          <ul style={{ marginTop: 6, paddingLeft: 18 }}>
                            {(socReport.gaps ?? []).map((g, i) => (
                              <li key={i} style={{ marginBottom: 6 }}>
                                {g}
                              </li>
                            ))}
                            {(socReport.gaps ?? []).length === 0 && (
                              <li style={{ color: MUTED }}>—</li>
                            )}
                          </ul>
                        </div>
                      </div>
                    </details>
                  )}
                </div>
              )}
            </div>
          </div>
        </aside>
      </div>
    </main>
  );
}
