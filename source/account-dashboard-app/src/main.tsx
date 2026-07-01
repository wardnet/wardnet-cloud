import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

// Design-system styles: tokens (:root + [data-theme=dark]) then component CSS.
import "@wardnet/styles";
import "@wardnet/ui/styles.css";
import "./styles/app.css";

import { App } from "./App";
import { MSW_ENABLED } from "./config/env";

async function bootstrap() {
  if (MSW_ENABLED) {
    const { startMockWorker } = await import("./mocks/browser");
    await startMockWorker();
  }
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}

void bootstrap();
