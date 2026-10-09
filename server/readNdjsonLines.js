// Bound both the pending line and the complete upload before parsing NDJSON.
// Line length is measured in bytes, excluding LF and an optional CR before LF.
const limitError = (message) => Object.assign(new Error(message), { statusCode: 413 });

export async function* readNdjsonLines(input, { max_line_bytes, max_stream_bytes }) {
  let fragments = [];
  let pendingBytes = 0;
  let totalBytes = 0;

  const append = (segment) => {
    pendingBytes += segment.length;
    if (pendingBytes > max_line_bytes + 1) throw limitError("governance stream line exceeds max_line_bytes");
    if (segment.length) fragments.push(segment);
  };
  const complete = () => {
    let line = Buffer.concat(fragments, pendingBytes);
    if (line.at(-1) === 13) line = line.subarray(0, -1);
    if (line.length > max_line_bytes) throw limitError("governance stream line exceeds max_line_bytes");
    fragments = [];
    pendingBytes = 0;
    return line.toString("utf8");
  };

  for await (const part of input) {
    const chunk = Buffer.isBuffer(part) ? part : Buffer.from(part);
    totalBytes += chunk.length;
    if (totalBytes > max_stream_bytes) throw limitError("governance stream exceeds max_stream_bytes");

    let start = 0;
    while (start < chunk.length) {
      const newline = chunk.indexOf(10, start);
      if (newline === -1) {
        append(chunk.subarray(start));
        break;
      }
      append(chunk.subarray(start, newline));
      yield complete();
      start = newline + 1;
    }
  }
  if (pendingBytes) yield complete();
}
