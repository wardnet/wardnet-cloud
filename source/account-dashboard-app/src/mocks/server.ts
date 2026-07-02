import { setupServer } from "msw/node";
import { handlers } from "./handlers";

/** Node MSW server for Vitest integration tests. */
export const server = setupServer(...handlers);
