# x402 Header Diagnostics

Paid API for validating x402 v2 payment challenges and signatures before shipping an integration.

## Live service

- Base URL: https://x402-header-diagnostics.vercel.app
- Paid endpoint: `POST /api/diagnose`
- Price: `0.10 USDC` per diagnostic
- Network: Base Mainnet (`eip155:8453`)
- Settlement address: `0x465A003Ad9B708e0EFe291656BDF8a2b52cf0683`

## Free endpoints

```text
GET /api
GET /api/health
```

## Paid request

Send one or more of the following fields as JSON:

```json
{
  "paymentRequired": "base64-encoded PAYMENT-REQUIRED header",
  "paymentSignature": "base64-encoded PAYMENT-SIGNATURE header",
  "challenge": { "x402Version": 2, "accepts": [] }
}
```

Without a valid x402 payment, the endpoint returns HTTP `402` and advertises the payment requirements. An x402-compatible client can sign the Base USDC authorization and retry automatically.

The response includes a compatibility score, structured errors and warnings, detected networks, signature structure checks, and Bazaar discovery metadata checks.

## Support

Open a GitHub issue with a sanitized payload or contact `dnghst.78@gmail.com`. Never publish private keys, API credentials, or wallet seed phrases.
