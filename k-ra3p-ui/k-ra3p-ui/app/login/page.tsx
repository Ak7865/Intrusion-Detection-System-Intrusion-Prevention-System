"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { getSession, signIn, signUp } from "@/lib/auth";
export default function Login() {
  const r = useRouter();
  const [mode, setMode] = useState<"in" | "up">("in");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { if (getSession()) r.replace("/dashboard"); }, [r]);
  const submit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault(); setErr(""); setBusy(true);
    const f = new FormData(e.currentTarget);
    const [name, email, pw] = [String(f.get("name") || ""), String(f.get("email")), String(f.get("password"))];
    try { if (mode === "up") await signUp(name, email, pw); else await signIn(email, pw); r.push("/dashboard"); }
    catch (x) { setErr((x as Error).message); setBusy(false); }
  };
  const switchTo = (m: "in" | "up") => { setMode(m); setErr(""); };
  return (
    <main className="auth">
      <section className="auth-l">
        <span style={{ width: 44, height: 44, borderRadius: 8, background: "var(--primary)", display: "grid", placeItems: "center", marginBottom: 16 }}><ShieldCheck color="#fff" /></span>
        <h3>Welcome to K-RA³P</h3>
        <p className="b3 muted" style={{ marginTop: 8 }}>Sign in to monitor threats and manage defenses in one place.</p>
      </section>
      <section className="auth-r">
        <form onSubmit={submit} className="field" style={{ width: 360, maxWidth: "100%" }}>
          <div className="tabs">
            <button type="button" className={mode === "in" ? "on" : ""} onClick={() => switchTo("in")}>Sign in</button>
            <button type="button" className={mode === "up" ? "on" : ""} onClick={() => switchTo("up")}>Sign up</button>
          </div>
          <h4 style={{ marginBottom: 16 }}>{mode === "in" ? "Sign in" : "Create account"}</h4>
          {mode === "up" && <><label htmlFor="n">Full name</label><input id="n" name="name" placeholder="Your name" required /></>}
          <label htmlFor="e">Email</label><input id="e" name="email" type="email" placeholder="you@email.com" required />
          <label htmlFor="p">Password</label><input id="p" name="password" type="password" placeholder="••••••••" minLength={8} required />
          {err && <p className="err" role="alert">{err}</p>}
          {mode === "in" && <div className="b4" style={{ textAlign: "right", marginBottom: 16 }}><a href="#" style={{ color: "var(--s2)", textDecoration: "underline" }}>Forgot password?</a></div>}
          <button className="btn btn-primary" style={{ width: "100%" }} disabled={busy}>{busy ? "Please wait…" : mode === "in" ? "Sign in" : "Create account"}</button>
          <p className="b4" style={{ textAlign: "center", marginTop: 16 }}>
            {mode === "in" ? "No account? " : "Have an account? "}
            <a href="#" onClick={(e) => { e.preventDefault(); switchTo(mode === "in" ? "up" : "in"); }} style={{ color: "var(--s2)", textDecoration: "underline" }}>{mode === "in" ? "Sign up" : "Sign in"}</a>
          </p>
        </form>
      </section>
    </main>
  );
}
