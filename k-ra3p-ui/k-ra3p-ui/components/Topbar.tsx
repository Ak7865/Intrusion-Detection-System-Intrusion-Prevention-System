"use client";
import { Search, Bell, LogOut } from "lucide-react";
import { useRouter } from "next/navigation";
import { signOut, type User } from "@/lib/auth";
export default function Topbar({ user }: { user: User }) {
  const r = useRouter();
  return (
    <header className="top">
      <label className="search"><Search size={16} /><input placeholder="Search" aria-label="Search" /></label>
      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <Bell size={18} color="var(--grey)" />
        <span className="avatar" title={user.email}>{user.name.charAt(0).toUpperCase()}</span>
        <button className="btn btn-tertiary sm" onClick={() => { signOut(); r.replace("/login"); }}><LogOut size={14} />Sign out</button>
      </div>
    </header>
  );
}
