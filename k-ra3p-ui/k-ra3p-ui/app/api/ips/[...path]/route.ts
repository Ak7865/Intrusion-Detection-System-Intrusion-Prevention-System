import { NextRequest, NextResponse } from "next/server";

// Proxy to the Python IPS API backend.
// The backend URL is configured via IPS_API_URL environment variable.
// This route catches /api/ips/* and forwards to the backend at the same sub-path.

const BACKEND = process.env.IPS_API_URL || "http://192.168.56.1:8765";

async function proxyRequest(req: NextRequest, pathSegments: string[], method: string) {
  const sub = pathSegments.join("/");
  const search = req.nextUrl.search || "";
  const url = `${BACKEND}/api/${sub}${search}`;

  try {
    const init: RequestInit = {
      method,
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    };
    if (method !== "GET" && method !== "HEAD") {
      const body = await req.text();
      if (body) {
        (init as Record<string, unknown>).body = body;
        (init as Record<string, unknown>).headers = { "Content-Type": "application/json" };
      }
    }
    const upstream = await fetch(url, init);
    const data = await upstream.json();
    return NextResponse.json(data, { status: upstream.status });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json(
      { error: "backend_unreachable", detail: message },
      { status: 503 }
    );
  }
}

export async function GET(
  req: NextRequest,
  { params }: { params: { path: string[] } }
) {
  return proxyRequest(req, params.path, "GET");
}

export async function POST(
  req: NextRequest,
  { params }: { params: { path: string[] } }
) {
  return proxyRequest(req, params.path, "POST");
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: { path: string[] } }
) {
  return proxyRequest(req, params.path, "DELETE");
}

export async function PUT(
  req: NextRequest,
  { params }: { params: { path: string[] } }
) {
  return proxyRequest(req, params.path, "PUT");
}

