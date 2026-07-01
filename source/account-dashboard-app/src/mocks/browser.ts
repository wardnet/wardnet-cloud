import { setupWorker } from "msw/browser";
import { handlers } from "./handlers";

export const worker = setupWorker(...handlers);

/** Start MSW in the browser; resolves once the worker is ready. */
export async function startMockWorker() {
  await worker.start({
    onUnhandledRequest: "bypass",
    quiet: true,
  });
}
