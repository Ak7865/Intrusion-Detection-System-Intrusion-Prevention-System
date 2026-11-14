import { ShieldCheck } from "lucide-react";
export default function Logo({ name = "K-RA³P" }: { name?: string }) {
  return <div className="logo"><i><ShieldCheck size={18} color="#fff" /></i>{name}</div>;
}
