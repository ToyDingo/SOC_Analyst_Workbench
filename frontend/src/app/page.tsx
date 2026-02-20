"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { apiBase } from "@/lib/apiBase";

type LoginResponse = {
  access_token: string;
  token_type: string;
};

const PAGE_BG = "#e9ecef";
const SHELL_BG = "#2b2b2b";
const PANEL_BG = "#f6f7f9";
const CARD_BG = "#ffffff";
const BORDER = "#cfd6de";
const TEXT = "#1f2937";
const MUTED = "#6b7280";
const ACCENT = "#1e88e5";
const ACCENT_DIM = "#e8f1ff";
const BTN_BG = "#f3f4f6";

// ✅ update these 3 fields
const CREATOR = {
  name: "Kevin L Ford",
  email: "ford.kevin@gmail.com",
  github: "https://github.com/ToyDingo/SOC_Analyst_Workbench",
};

function Pill({
  text,
  tone,
  onClick,
  selected,
  disabled,
}: {
  text: string;
  tone?: "neutral" | "info" | "good" | "warn" | "bad";
  onClick?: () => void;
  selected?: boolean;
  disabled?: boolean;
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
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      style={{
        background: selected ? ACCENT_DIM : bg,
        color: selected ? "#0b4aa2" : fg,
        padding: "6px 12px",
        borderRadius: 999,
        fontSize: 12,
        border: selected ? `1px solid ${ACCENT}` : `1px solid ${BORDER}`,
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.6 : 1,
        fontWeight: 800,
      }}
    >
      {text}
    </button>
  );
}

function CreatorInfoFab() {
  const [open, setOpen] = useState(false);

  return (
    <div style={{ position: "fixed", right: 18, bottom: 18, zIndex: 50 }}>
      {/* Expanded panel */}
      {open && (
        <div
          style={{
            width: 320,
            marginBottom: 10,
            background: PANEL_BG,
            border: `1px solid ${BORDER}`,
            borderRadius: 14,
            padding: 10,
            boxShadow: "0 12px 28px rgba(0,0,0,0.18)",
          }}
        >
          <div
            style={{
              background: CARD_BG,
              border: `1px solid ${BORDER}`,
              borderRadius: 12,
              padding: 12,
              display: "grid",
              gap: 10,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
              <div style={{ fontWeight: 900, letterSpacing: 0.2 }}>Creator info</div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                style={{
                  padding: "6px 10px",
                  borderRadius: 10,
                  border: `1px solid ${BORDER}`,
                  background: BTN_BG,
                  cursor: "pointer",
                  fontWeight: 900,
                }}
                aria-label="Close creator info"
                title="Close"
              >
                ✕
              </button>
            </div>

            <div style={{ display: "grid", gap: 8, fontSize: 13, color: TEXT }}>
              <div>
                <div style={{ color: MUTED, fontSize: 12, fontWeight: 800 }}>Name</div>
                <div style={{ fontWeight: 800 }}>{CREATOR.name}</div>
              </div>

              <div>
                <div style={{ color: MUTED, fontSize: 12, fontWeight: 800 }}>Email</div>
                <a
                  href={`mailto:${CREATOR.email}`}
                  style={{ color: "#0b4aa2", fontWeight: 800, textDecoration: "none" }}
                >
                  {CREATOR.email}
                </a>
              </div>

              <div>
                <div style={{ color: MUTED, fontSize: 12, fontWeight: 800 }}>GitHub</div>
                <a
                  href={CREATOR.github}
                  target="_blank"
                  rel="noreferrer"
                  style={{ color: "#0b4aa2", fontWeight: 800, textDecoration: "none", overflowWrap: "anywhere" }}
                >
                  {CREATOR.github}
                </a>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Floating pill button */}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        style={{
          borderRadius: 999,
          padding: "10px 14px",
          border: `1px solid ${open ? ACCENT : BORDER}`,
          background: open ? ACCENT_DIM : CARD_BG,
          color: open ? "#0b4aa2" : TEXT,
          cursor: "pointer",
          fontWeight: 900,
          display: "inline-flex",
          alignItems: "center",
          gap: 8,
          boxShadow: "0 10px 24px rgba(0,0,0,0.14)",
        }}
        aria-expanded={open}
        aria-label="Creator info"
        title="Creator info"
      >
        <span
          style={{
            width: 10,
            height: 10,
            borderRadius: 999,
            background: open ? ACCENT : "#6b7280",
            display: "inline-block",
          }}
        />
        Creator info
      </button>
    </div>
  );
}

export default function Home() {
  const router = useRouter();
  const API_BASE = useMemo(
    () => process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000",
    []
  );

  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("test@example.com");
  const [password, setPassword] = useState("Password123!");

  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [okMsg, setOkMsg] = useState<string | null>(null);

  useEffect(() => {
    async function checkToken() {
      const token = localStorage.getItem("access_token");
      if (!token) return;

      try {
        const res = await fetch(`${apiBase()}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (res.ok) router.push("/upload");
        else localStorage.removeItem("access_token");
      } catch {
        // backend unreachable: stay put
      }
    }
    checkToken();
  }, [router]);

  async function submit() {
    setLoading(true);
    setMsg(null);
    setOkMsg(null);

    try {
      if (mode === "login") {
        const res = await fetch(`${apiBase()}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data?.detail ?? "Login failed");

        const token = (data as LoginResponse).access_token;
        if (!token) throw new Error("Login failed: no token returned");

        localStorage.setItem("access_token", token);
        router.push("/upload");
        return;
      }

      const regRes = await fetch(`${apiBase()}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const regData = await regRes.json();
      if (!regRes.ok) throw new Error(regData?.detail ?? "Registration failed");

      const loginRes = await fetch(`${apiBase()}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const loginData = await loginRes.json();
      if (!loginRes.ok)
        throw new Error(loginData?.detail ?? "Login after register failed");

      const token = (loginData as LoginResponse).access_token;
      if (!token) throw new Error("Login failed: no token returned");

      localStorage.setItem("access_token", token);
      router.push("/upload");
    } catch (e: any) {
      setMsg(e?.message ?? "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

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
        <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
          <div style={{ fontWeight: 900, letterSpacing: 0.4, color: "#ffffff" }}>
            SOC Analyst Workbench
          </div>
          <div style={{ color: "#d1d5db", fontSize: 13 }}>
            Log Investigation Pipeline
          </div>
        </div>
      </div>

      {/* Centered content */}
      <div
        style={{
          minHeight: "calc(100vh - 58px)",
          display: "grid",
          placeItems: "center",
          padding: 16,
        }}
      >
        <div
          style={{
            width: "min(520px, 92vw)",
            background: PANEL_BG,
            border: `1px solid ${BORDER}`,
            borderRadius: 14,
            padding: 12,
          }}
        >
          <div
            style={{
              background: CARD_BG,
              border: `1px solid ${BORDER}`,
              borderRadius: 14,
              padding: 18,
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: 12,
              }}
            >
              <div>
                <div
                  style={{
                    fontWeight: 900,
                    fontSize: 18,
                    letterSpacing: 0.2,
                  }}
                >
                  {mode === "login" ? "Login" : "Create account"}
                </div>
              </div>

              <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
                <Pill
                  text="Login"
                  tone="info"
                  selected={mode === "login"}
                  disabled={loading}
                  onClick={() => {
                    setMsg(null);
                    setOkMsg(null);
                    setMode("login");
                  }}
                />
                <Pill
                  text="Register"
                  tone="info"
                  selected={mode === "register"}
                  disabled={loading}
                  onClick={() => {
                    setMsg(null);
                    setOkMsg(null);
                    setMode("register");
                  }}
                />
              </div>
            </div>

            <div style={{ marginTop: 14, display: "grid", gap: 10 }}>
              <label style={{ display: "grid", gap: 6 }}>
                <span style={{ fontSize: 12, color: MUTED, fontWeight: 700 }}>
                  Email
                </span>
                <input
                  placeholder="Email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  style={{
                    padding: "10px 12px",
                    borderRadius: 10,
                    border: `1px solid ${BORDER}`,
                    background: BTN_BG,
                    color: TEXT,
                    outline: "none",
                  }}
                />
              </label>

              <label style={{ display: "grid", gap: 6 }}>
                <span style={{ fontSize: 12, color: MUTED, fontWeight: 700 }}>
                  Password
                </span>
                <input
                  placeholder="Password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={{
                    padding: "10px 12px",
                    borderRadius: 10,
                    border: `1px solid ${BORDER}`,
                    background: BTN_BG,
                    color: TEXT,
                    outline: "none",
                  }}
                />
              </label>

              <button
                onClick={submit}
                disabled={loading || !email || !password}
                style={{
                  marginTop: 6,
                  padding: "11px 12px",
                  borderRadius: 10,
                  border: `1px solid ${BORDER}`,
                  background: loading ? ACCENT_DIM : BTN_BG,
                  color: TEXT,
                  cursor: loading ? "not-allowed" : "pointer",
                  fontWeight: 900,
                }}
              >
                {loading
                  ? "Working..."
                  : mode === "login"
                  ? "Login"
                  : "Create account"}
              </button>

              {okMsg && (
                <div
                  style={{
                    marginTop: 4,
                    background: "#e9f7ef",
                    color: "#0f5132",
                    border: `1px solid ${BORDER}`,
                    borderRadius: 12,
                    padding: 10,
                    fontSize: 13,
                    fontWeight: 700,
                  }}
                >
                  {okMsg}
                </div>
              )}

              {msg && (
                <div
                  style={{
                    marginTop: 4,
                    background: "#fdecec",
                    color: "#7f1d1d",
                    border: `1px solid ${BORDER}`,
                    borderRadius: 12,
                    padding: 10,
                    fontSize: 13,
                    fontWeight: 700,
                  }}
                >
                  Error: {msg}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ✅ Creator info bubble (bottom-right) */}
      <CreatorInfoFab />
    </main>
  );
}