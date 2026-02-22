import net from "node:net";
import { describe, expect, it, vi } from "vitest";
import {
  buildPortHints,
  classifyPortListener,
  ensurePortAvailable,
  formatPortDiagnostics,
  handlePortError,
  PortInUseError,
} from "./ports.js";

describe("ports helpers", () => {
  it("ensurePortAvailable rejects when port busy", async () => {
    const server = net.createServer();
    await new Promise((resolve) => server.listen(0, resolve));
    const port = (server.address() as net.AddressInfo).port;
    await expect(ensurePortAvailable(port)).rejects.toBeInstanceOf(PortInUseError);
    server.close();
  });

  it("handlePortError exits nicely on EADDRINUSE", async () => {
    const runtime = {
      error: vi.fn(),
      log: vi.fn(),
      exit: vi.fn() as unknown as (code: number) => never,
    };
    // Avoid slow OS port inspection; this test only cares about messaging + exit behavior.
    await handlePortError(new PortInUseError(1234, "details"), 1234, "context", runtime).catch(
      () => {},
    );
    expect(runtime.error).toHaveBeenCalled();
    expect(runtime.exit).toHaveBeenCalledWith(1);
  });

  it("classifies ssh and gateway listeners", () => {
    expect(
      classifyPortListener({ commandLine: "ssh -N -L 40104:127.0.0.1:40104 user@host" }, 40104),
    ).toBe("ssh");
    expect(
      classifyPortListener(
        {
          commandLine: "node /Users/me/Projects/openclaw/dist/entry.js gateway",
        },
        40104,
      ),
    ).toBe("gateway");
  });

  it("formats port diagnostics with hints", () => {
    const diagnostics = {
      port: 40104,
      status: "busy" as const,
      listeners: [{ pid: 123, commandLine: "ssh -N -L 40104:127.0.0.1:40104" }],
      hints: buildPortHints([{ pid: 123, commandLine: "ssh -N -L 40104:127.0.0.1:40104" }], 40104),
    };
    const lines = formatPortDiagnostics(diagnostics);
    expect(lines[0]).toContain("Port 40104 is already in use");
    expect(lines.some((line) => line.includes("SSH tunnel"))).toBe(true);
  });
});
