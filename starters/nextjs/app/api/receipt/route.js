import { evaluateDemo } from "../../../lib/demo.mjs";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export function GET() {
  const { result } = evaluateDemo();
  return Response.json(result.receipt, {
    headers: { "cache-control": "no-store" }
  });
}
