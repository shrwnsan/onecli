import { type NextRequest, NextResponse } from "next/server";
import { loadCaCertificate } from "@/lib/gateway-ca";
import { resolveApiAuth } from "@/lib/api-auth";
import { unauthorized } from "@/lib/api-utils";

export async function GET(request: NextRequest) {
  const auth = await resolveApiAuth(request);
  if (!auth) return unauthorized();

  const pem = loadCaCertificate();

  if (!pem) {
    return NextResponse.json(
      {
        error:
          "CA certificate not available. Start the gateway first to generate it.",
      },
      { status: 503 },
    );
  }

  return new NextResponse(pem, {
    status: 200,
    headers: {
      "content-type": "application/x-pem-file",
      "content-disposition": 'attachment; filename="onecli-gateway-ca.pem"',
    },
  });
}
