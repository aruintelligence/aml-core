// AML brand timestamp profile: explicit RFC 3339-style offset, uppercase T/Z,
// 1–3 fractional digits, years 0001–9999, and no leap-second representation.
// Validate the calendar first: Date.parse alone normalizes dates like February 30.
const timestampPattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-](\d{2}):(\d{2}))$/;

export function parseBrandTime(value) {
  if (typeof value !== "string") return null;
  const parts = timestampPattern.exec(value);
  if (!parts) return null;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, , offset, offsetHourText, offsetMinuteText] = parts;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > days[month - 1] ||
      hour > 23 || minute > 59 || second > 59 ||
      (offset !== "Z" && (Number(offsetHourText) > 23 || Number(offsetMinuteText) > 59))) {
    return null;
  }
  const instant = Date.parse(value);
  return Number.isFinite(instant) ? instant : null;
}
