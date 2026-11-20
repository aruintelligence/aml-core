import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { canonicalJSONStringify } from "../../protocol/canonicalJson.js";
import { parseJsonWithoutDuplicateKeys } from "../../runtime/strictJson.js";

export function verifyPaymentReceipt(receipt, { operationId, requestBytes, destinationKey }) {
  const expected = {
    profile: "aml-sandbox-payment-status/1",
    destination: "sandbox-payment-ledger",
    operation_id: operationId,
    request_sha256: createHash("sha256").update(requestBytes).digest("hex"),
    outcome: "recorded"
  };
  if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(operationId)
    || destinationKey.type !== "public" || destinationKey.asymmetricKeyType !== "ed25519"
    || typeof receipt?.signature_hex !== "string" || !/^[a-f0-9]{128}$/.test(receipt.signature_hex)
    || Object.keys(receipt).length !== 2 || !receipt.statement) return false;

  const signed = canonicalJSONStringify(receipt.statement);
  return signed === canonicalJSONStringify(expected)
    && verify(null, Buffer.from(signed), destinationKey, Buffer.from(receipt.signature_hex, "hex"));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [receiptFile, requestFile, operationId, keyFile, ...extra] = process.argv.slice(2);
    if (!keyFile || extra.length) throw new Error("Usage: verify-payment-receipt.mjs RECEIPT REQUEST OPERATION_ID DESTINATION_PUBLIC_PEM");
    const receipt = parseJsonWithoutDuplicateKeys(readFileSync(receiptFile, "utf8"));
    const verified = verifyPaymentReceipt(receipt, {
      operationId, requestBytes: readFileSync(requestFile), destinationKey: createPublicKey(readFileSync(keyFile))
    });
    console.log(JSON.stringify({ verified, outcome: verified ? "recorded" : "unverified" }));
    process.exitCode = verified ? 0 : 1;
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
  }
}
