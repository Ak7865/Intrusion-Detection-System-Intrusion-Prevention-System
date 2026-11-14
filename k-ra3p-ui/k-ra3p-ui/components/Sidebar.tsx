"use client";
import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutDashboard, Radar, Network, ScrollText, Bug, FileText, Settings, ChevronDown } from "lucide-react";
import Logo from "./Logo";

type Item = { label: string; href?: string; icon: React.ReactNode; children?: { label: string; href: string }[] };
const NAV: Item[] = [
  { label: "Dashboard", href: "/dashboard", icon: <LayoutDashboard size={18} /> },
  { label: "Threat detection", icon: <Radar size={18} />, children: [
    { label: "Alerts", href: "/threats/alerts" }, { label: "Detection rules", href: "/threats/rules" }, { label: "Blocked IPs", href: "/threats/blocked" } ] },
  { label: "Network", icon: <Network size={18} />, children: [
    { label: "Nodes", href: "/network/nodes" }, { label: "Traffic", href: "/network/traffic" } ] },
  { label: "Audit log", href: "/audit", icon: <ScrollText size={18} /> },
  { label: "Vulnerabilities", href: "/vulnerabilities", icon: <Bug size={18} /> },
  { label: "Reports", href: "/reports", icon: <FileText size={18} /> },
  { label: "Settings", icon: <Settings size={18} />, children: [
    { label: "Users", href: "/settings/users" }, { label: "API keys", href: "/settings/api-keys" } ] },
];

export default function Sidebar() {
  const path = usePathname();
  const [open, setOpen] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(NAV.filter(n => n.children?.some(c => path.startsWith(c.href))).map(n => [n.label, true])));
  return (
    <aside className="side" aria-label="Main navigation">
      <Logo />
      <nav>
        {NAV.map((n) => n.children ? (
          <div key={n.label}>
            <button className={`nav-item ${open[n.label] ? "open" : ""}`} aria-expanded={!!open[n.label]}
              onClick={() => setOpen({ ...open, [n.label]: !open[n.label] })}>
              {n.icon}{n.label}<ChevronDown size={16} className="chev" />
            </button>
            {open[n.label] && <div className="sub">
              {n.children.map(c => <Link key={c.href} href={c.href} className={`nav-item ${path === c.href ? "active" : ""}`}>{c.label}</Link>)}
            </div>}
          </div>
        ) : (
          <Link key={n.label} href={n.href!} className={`nav-item ${path === n.href ? "active" : ""}`}>{n.icon}{n.label}</Link>
        ))}
      </nav>
    </aside>
  );
}
