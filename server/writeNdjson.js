// Wait for the transport when a client reads more slowly than we produce
// decisions. A bounded upload must not become an unbounded response queue.
const closed = () => Object.assign(new Error("response_closed"), { code: "AML_RESPONSE_CLOSED" });

export async function writeNdjson(res, value) {
  if (res.destroyed || res.writableEnded) throw closed();
  if (res.write(`${JSON.stringify(value)}\n`)) return;

  await new Promise((resolve, reject) => {
    const cleanup = () => {
      res.off("drain", onDrain);
      res.off("close", onClose);
      res.off("error", onError);
    };
    const onDrain = () => {
      cleanup();
      resolve();
    };
    const onClose = () => {
      cleanup();
      reject(closed());
    };
    const onError = () => {
      cleanup();
      reject(closed());
    };

    res.once("drain", onDrain);
    res.once("close", onClose);
    res.once("error", onError);
    if (res.destroyed || res.writableEnded) onClose();
  });
}
