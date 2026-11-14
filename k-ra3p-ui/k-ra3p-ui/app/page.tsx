"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { getSession } from "@/lib/auth";
export default function Loading() {
  const r = useRouter();
  useEffect(() => { const t = setTimeout(() => r.replace(getSession() ? "/dashboard" : "/login"), 1600); return () => clearTimeout(t); }, [r]);
  return (
    <main className="loading">
      <span style={{ width: 44, height: 44, borderRadius: 8, background: "var(--primary)", display: "grid", placeItems: "center" }}><ShieldCheck color="#fff" /></span>
      <h4>K-RA³P</h4><div className="bar" /><span className="b4" style={{ color: "var(--lgrey)" }}>Loading…</span>
    </main>
  );
}
