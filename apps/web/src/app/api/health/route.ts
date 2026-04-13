import { type NextRequest, NextResponse } from "next/server";
import { resolveApiAuth } from "@/lib/api-auth";
import { unauthorized } from "@/lib/api-utils";

export async function GET(request: NextRequest) {
  const auth = await resolveApiAuth(request);
  if (!auth) return unauthorized();

  return NextResponse.json({
    status: "ok",
  });
}
