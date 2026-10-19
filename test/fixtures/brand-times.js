export const acceptedBrandTimes = [
  "0001-01-01T00:00:00Z",
  "2024-02-29T23:59:59.999Z",
  "2000-02-29T00:00:00Z",
  "2024-03-01T01:59:59.999+02:00",
  "2024-02-29T21:59:59.999-02:00",
  "2026-01-01T00:00:00.1Z"
];

export const impossibleBrandTime = "2026-02-30T00:00:00Z";
export const timezoneFreeBrandTime = "2026-01-01T00:00:00";

export const rejectedBrandTimes = [
  impossibleBrandTime, // Date.parse normalizes this into March.
  "2023-02-29T00:00:00Z",
  "1900-02-29T00:00:00Z", "2100-02-29T00:00:00Z",
  "2024-04-31T00:00:00Z",
  timezoneFreeBrandTime, // No verifier-local timezone.
  "2026-01-01", "2026-01-01 00:00:00Z", "0",
  "0000-01-01T00:00:00Z",
  "2026-01-01T24:00:00Z", "2026-01-01T00:00:60Z",
  "2026-01-01T00:00:00.1234Z",
  "2026-01-01T00:00:00+24:00", "2026-01-01T00:00:00+02:60"
];
