// DEMO auth: accounts live in this browser's localStorage. Replace with a real backend before production.
export type User = { name: string; email: string };
const U = "kra3p_users", S = "kra3p_session";
async function hash(s: string) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(b)).map((x) => x.toString(16).padStart(2, "0")).join("");
}
const users = (): { name: string; email: string; h: string }[] => { try { return JSON.parse(localStorage.getItem(U) || "[]"); } catch { return []; } };
export async function signUp(name: string, email: string, pw: string) {
  const us = users(); email = email.trim().toLowerCase();
  if (us.some((u) => u.email === email)) throw new Error("An account with this email already exists. Sign in instead.");
  us.push({ name, email, h: await hash(pw) });
  localStorage.setItem(U, JSON.stringify(us));
  localStorage.setItem(S, JSON.stringify({ name, email }));
}
export async function signIn(email: string, pw: string) {
  email = email.trim().toLowerCase();
  const u = users().find((x) => x.email === email);
  if (!u || u.h !== (await hash(pw))) throw new Error("Email or password is incorrect.");
  localStorage.setItem(S, JSON.stringify({ name: u.name, email }));
}
export const getSession = (): User | null => { try { return JSON.parse(localStorage.getItem(S) || "null"); } catch { return null; } };
export const signOut = () => localStorage.removeItem(S);
