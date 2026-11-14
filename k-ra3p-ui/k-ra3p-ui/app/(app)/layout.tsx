"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";
import { getSession, type User } from "@/lib/auth";
export default function AppLayout({ children }: { children: React.ReactNode }) {
  const r = useRouter();
  const [user, setUser] = useState<User | null>(null);
  useEffect(() => { const s = getSession(); if (!s) r.replace("/login"); else setUser(s); }, [r]);
  if (!user) return <div className="loading" />;
  return (
    <div className="shell">
      <Sidebar />
      <div className="main"><Topbar user={user} /><div className="content">{children}</div></div>
    </div>
  );
}
