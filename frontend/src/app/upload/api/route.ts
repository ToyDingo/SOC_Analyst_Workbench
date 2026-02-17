import { NextRequest, NextResponse } from "next/server";

const API_BASE_URL = process.env.API_BASE_URL; // set at Cloud Run runtime

async function handler(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  if (!API_BASE_URL) {
    return NextResponse.json(
      { detail: "Missing API_BASE_URL env var on web service" },
      { status: 500 }
    );
  }

  const { path } = await ctx.params;
  const url = new URL(req.url);
  const target = `${API_BASE_URL}/${path.join("/")}${url.search}`;

  // Copy headers (especially Authorization) through
  const headers = new Headers(req.headers);
  headers.delete("host");

  const init: RequestInit = {
    method: req.method,
    headers,
    redirect: "manual",
  };

  // Only attach body for methods that can have one
  if (!["GET", "HEAD"].includes(req.method)) {
    init.body = await req.arrayBuffer();
  }

  const resp = await fetch(target, init);

  // Stream back response
  const respHeaders = new Headers(resp.headers);
  respHeaders.delete("content-encoding"); // avoid gzip/br mismatch issues

  return new NextResponse(resp.body, {
    status: resp.status,
    headers: respHeaders,
  });
}

export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const PATCH = handler;
export const DELETE = handler;
export const OPTIONS = handler;
