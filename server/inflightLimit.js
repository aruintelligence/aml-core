export function createInflightLimit(maxInflightRequests = 100) {
  if (!Number.isSafeInteger(maxInflightRequests) || maxInflightRequests < 1) {
    throw new TypeError("max_inflight_requests must be a positive safe integer");
  }

  let active = 0;
  return {
    acquire(res) {
      if (active >= maxInflightRequests) return false;
      active += 1;
      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        active -= 1;
        res.off("finish", release);
        res.off("close", release);
      };
      res.once("finish", release);
      res.once("close", release);
      return true;
    }
  };
}
