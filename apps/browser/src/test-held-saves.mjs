import { createDocumentScope, heldSaves } from "./test-native-stub.mjs";

export function holdDocumentSaves(context, work) {
  const scope = createDocumentScope();
  const queued = Promise.withResolvers();
  const aborted = Promise.withResolvers();
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    scope.close();
    heldSaves.onQueued = null;
    heldSaves.on = false;
    for (const land of heldSaves.queue.splice(0)) land();
    context.signal.removeEventListener("abort", cancel);
  };
  const cancel = () => {
    close();
    aborted.reject(context.signal.reason ?? new Error("Held document save cancelled"));
  };
  context.after(close);
  context.signal.addEventListener("abort", cancel, { once: true });
  heldSaves.on = true;
  heldSaves.onQueued = queued.resolve;
  const pending = context.signal.aborted
    ? Promise.reject(context.signal.reason)
    : Promise.resolve().then(() => {
      context.signal.throwIfAborted();
      return scope.run(work);
    });
  const waiting = Promise.race([
    queued.promise,
    pending.then(() => { throw new Error("Operation completed without enqueueing a held document save"); }),
    aborted.promise,
  ]).catch((error) => {
    close();
    throw error;
  });
  if (context.signal.aborted) cancel();
  return { queued: waiting, pending, close };
}
