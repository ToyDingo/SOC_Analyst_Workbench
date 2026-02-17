"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

type LoginResponse = {
  access_token: string;
  token_type: string;
};

export default function Home() {
  const router = useRouter();
  // const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
  const API_BASE = "/api";

  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("test@example.com");
  const [password, setPassword] = useState("Password123!");

  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  // Only auto-redirect if token is VALID
  useEffect(() => {
    async function checkToken() {
      const token = localStorage.getItem("access_token");
      if (!token) return;

      try {
        const res = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (res.ok) {
          router.push("/upload");
        } else {
          // token exists but is invalid/expired
          localStorage.removeItem("access_token");
        }
      } catch {
        // If backend unreachable, stay on login page
      }
    }

    checkToken();
  }, [API_BASE, router]);

  async function submit() {
    setLoading(true);
    setMsg(null);

    try {
      if (mode === "login") {
        const res = await fetch(`${API_BASE}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        });

        const data = await res.json();

        if (!res.ok) {
          // 401 invalid creds
          throw new Error(data?.detail ?? "Login failed");
        }

        const token = (data as LoginResponse).access_token;
        if (!token) throw new Error("Login failed: no token returned");

        localStorage.setItem("access_token", token);
        router.push("/upload");
        return;
      }

      // mode === "register"
      const regRes = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const regData = await regRes.json();

      if (!regRes.ok) {
        // 409 means email already exists
        throw new Error(regData?.detail ?? "Registration failed");
      }

      // Registration succeeded — now login to get token
      const loginRes = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const loginData = await loginRes.json();

      if (!loginRes.ok) {
        throw new Error(loginData?.detail ?? "Login after register failed");
      }

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
    <main style={{ padding: 40, fontFamily: "sans-serif", maxWidth: 520 }}>
      <h1>{mode === "login" ? "Login" : "Register"}</h1>
      <p style={{ opacity: 0.7 }}>API base: {API_BASE}</p>

      <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
        <button
          onClick={() => {
            setMsg(null);
            setMode("login");
          }}
          disabled={loading}
          style={{ padding: "8px 12px", cursor: "pointer" }}
        >
          Login
        </button>

        <button
          onClick={() => {
            setMsg(null);
            setMode("register");
          }}
          disabled={loading}
          style={{ padding: "8px 12px", cursor: "pointer" }}
        >
          Register
        </button>
      </div>

      <div style={{ display: "grid", gap: 10 }}>
        <input
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          style={{ padding: 10 }}
        />

        <input
          placeholder="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{ padding: 10 }}
        />

        <button
          onClick={submit}
          disabled={loading || !email || !password}
          style={{ padding: "10px 12px", cursor: "pointer" }}
        >
          {loading ? "Working..." : mode === "login" ? "Login" : "Create account"}
        </button>

        {msg && <p style={{ color: "crimson" }}>Error: {msg}</p>}
      </div>
    </main>
  );
}
