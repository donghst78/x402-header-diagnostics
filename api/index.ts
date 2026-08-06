import { facilitator } from "@coinbase/x402";
import { HTTPFacilitatorClient, x402ResourceServer } from "@x402/core/server";
import { registerExactEvmScheme } from "@x402/evm/exact/server";
import { paymentMiddleware } from "@x402/hono";
import { Hono } from "hono";
import { handle } from "hono/vercel";

const PAY_TO = "0x465A003Ad9B708e0EFe291656BDF8a2b52cf0683";
const BASE_MAINNET = "eip155:8453";
const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

type Finding = {
  severity: "error" | "warning" | "info";
  code: string;
  message: string;
};

type DiagnosticRequest = {
  paymentRequired?: string;
  paymentSignature?: string;
  challenge?: unknown;
};

const app = new Hono();
// @coinbase/x402 currently bundles its own @x402/core type declarations.
// The runtime facilitator contract is compatible; this cast avoids duplicate-package type identity conflicts.
const resourceServer = new x402ResourceServer(new HTTPFacilitatorClient(facilitator as any));
registerExactEvmScheme(resourceServer);

app.use(
  paymentMiddleware(
    {
      "POST /api/diagnose": {
        accepts: [{ scheme: "exact", price: "$0.10", network: BASE_MAINNET, payTo: PAY_TO }],
        description: "Validate an x402 v2 PAYMENT-REQUIRED challenge or header and return actionable integration diagnostics.",
        mimeType: "application/json",
      },
    },
    resourceServer,
  ),
);

app.get("/api", (c) => c.json({
  service: "x402 Header Diagnostics",
  version: "1.0.0",
  network: BASE_MAINNET,
  asset: BASE_USDC,
  price: "$0.10",
  endpoint: "POST /api/diagnose",
}));

app.get("/api/health", (c) => c.json({ ok: true, service: "x402-header-diagnostics" }));

app.post("/api/diagnose", async (c) => {
  let body: DiagnosticRequest;
  try {
    body = await c.req.json<DiagnosticRequest>();
  } catch {
    return c.json({ error: "Request body must be valid JSON." }, 400);
  }

  if (!body || (!body.paymentRequired && !body.paymentSignature && !body.challenge)) {
    return c.json({ error: "Provide paymentRequired, paymentSignature, or a decoded challenge object." }, 400);
  }

  try {
    const challenge = body.challenge ?? (body.paymentRequired ? decodeBase64Json(body.paymentRequired, "paymentRequired") : undefined);
    const signature = body.paymentSignature ? decodeBase64Json(body.paymentSignature, "paymentSignature") : undefined;
    const findings: Finding[] = [];

    if (challenge) inspectChallenge(challenge, findings);
    if (signature) inspectSignature(signature, findings);

    const errors = findings.filter((f) => f.severity === "error").length;
    const warnings = findings.filter((f) => f.severity === "warning").length;

    return c.json({
      score: Math.max(0, 100 - errors * 25 - warnings * 8),
      compatible: errors === 0,
      summary: { errors, warnings, informational: findings.length - errors - warnings },
      findings,
      normalized: {
        x402Version: readField(challenge, "x402Version"),
        acceptedNetworks: extractNetworks(challenge),
        hasBazaarExtension: hasBazaarExtension(challenge),
        signatureVersion: readField(signature, "x402Version"),
      },
      checkedAt: new Date().toISOString(),
    });
  } catch (error) {
    return c.json({ error: error instanceof Error ? error.message : "Unable to decode input." }, 400);
  }
});

function decodeBase64Json(value: string, field: string): unknown {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${field} must be a non-empty string.`);
  if (value.length > 32_768) throw new Error(`${field} exceeds the 32 KiB safety limit.`);
  const cleaned = value.trim().replace(/^Bearer\s+/i, "");
  const padded = cleaned.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(cleaned.length / 4) * 4, "=");
  const decoded = Buffer.from(padded, "base64").toString("utf8");
  try { return JSON.parse(decoded) as unknown; }
  catch { throw new Error(`${field} does not decode to valid JSON.`); }
}

function inspectChallenge(value: unknown, findings: Finding[]): void {
  if (!isRecord(value)) {
    findings.push({ severity: "error", code: "challenge_not_object", message: "The payment challenge must decode to a JSON object." });
    return;
  }
  findings.push(value.x402Version === 2
    ? { severity: "info", code: "version_v2", message: "Challenge uses x402 v2." }
    : { severity: "error", code: "version_not_v2", message: "Expected x402Version 2." });
  if (!Array.isArray(value.accepts) || value.accepts.length === 0) {
    findings.push({ severity: "error", code: "accepts_missing", message: "Challenge must include at least one payment requirement." });
    return;
  }
  for (const [index, requirement] of value.accepts.entries()) {
    if (!isRecord(requirement)) {
      findings.push({ severity: "error", code: "requirement_not_object", message: `Payment requirement ${index} is not an object.` });
      continue;
    }
    if (requirement.scheme !== "exact" && requirement.scheme !== "upto") findings.push({ severity: "error", code: "unsupported_scheme", message: `Requirement ${index} uses an unsupported scheme.` });
    if (requirement.network !== BASE_MAINNET) findings.push({ severity: "warning", code: "network_not_base_mainnet", message: `Requirement ${index} does not target Base mainnet.` });
    if (typeof requirement.payTo !== "string" || !/^0x[a-fA-F0-9]{40}$/.test(requirement.payTo)) findings.push({ severity: "error", code: "invalid_pay_to", message: `Requirement ${index} has an invalid EVM payTo address.` });
    if (typeof requirement.asset === "string" && requirement.asset.toLowerCase() !== BASE_USDC.toLowerCase()) findings.push({ severity: "warning", code: "asset_not_base_usdc", message: `Requirement ${index} does not advertise native USDC on Base.` });
  }
  findings.push(hasBazaarExtension(value)
    ? { severity: "info", code: "bazaar_extension_present", message: "Bazaar discovery metadata is present." }
    : { severity: "warning", code: "bazaar_extension_missing", message: "No Bazaar extension was found; agent discovery may be limited." });
}

function inspectSignature(value: unknown, findings: Finding[]): void {
  if (!isRecord(value)) {
    findings.push({ severity: "error", code: "signature_not_object", message: "The payment signature must decode to a JSON object." });
    return;
  }
  if (value.x402Version !== 2) findings.push({ severity: "error", code: "signature_version_not_v2", message: "PAYMENT-SIGNATURE should use x402Version 2." });
  if (!isRecord(value.payload)) findings.push({ severity: "error", code: "signature_payload_missing", message: "PAYMENT-SIGNATURE is missing its payload object." });
  if (!isRecord(value.accepted)) findings.push({ severity: "warning", code: "accepted_requirement_missing", message: "PAYMENT-SIGNATURE does not include the accepted payment requirement." });
}

function extractNetworks(value: unknown): string[] {
  if (!isRecord(value) || !Array.isArray(value.accepts)) return [];
  return [...new Set(value.accepts.filter(isRecord).map((item) => item.network).filter((network): network is string => typeof network === "string"))];
}

function hasBazaarExtension(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (isRecord(value.extensions) && isRecord(value.extensions.bazaar)) return true;
  return Array.isArray(value.accepts) && value.accepts.some((item) => isRecord(item) && isRecord(item.extensions) && isRecord(item.extensions.bazaar));
}

function readField(value: unknown, key: string): unknown { return isRecord(value) ? value[key] : undefined; }
function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }

export default handle(app);
