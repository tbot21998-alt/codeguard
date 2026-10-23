import { spawnSync } from "node:child_process";

const ANALYZER = ["codeguard"];

export default async function CodeGuardPlugin() {
  return {
    "tool.execute.before": async (input, output) => {
      if (!["bash", "shell", "run_command"].includes(input?.tool)) return;
      const command = output?.args?.command ?? output?.args?.cmd ?? output?.args?.CommandLine;
      if (typeof command !== "string" || !command.trim()) {
        throw new Error("CodeGuard: Missing command; execution blocked.");
      }
      const analyzer = process.env.CODEGUARD_PYTHON
        ? [process.env.CODEGUARD_PYTHON, "-m", "guard"]
        : ANALYZER;
      const result = spawnSync(analyzer[0], [...analyzer.slice(1), "agent-hook", "--client", "opencode"], {
        input: JSON.stringify({ tool: input.tool, args: { command } }),
        encoding: "utf8",
        timeout: 30000,
        maxBuffer: 1024 * 1024,
        windowsHide: true,
        shell: false,
      });
      if (result.error || result.status !== 0 || result.signal) {
        throw new Error("CodeGuard: Inspector unavailable or failed; execution blocked.");
      }
      let decision;
      try {
        decision = JSON.parse(result.stdout);
      } catch {
        throw new Error("CodeGuard: Invalid inspector response; execution blocked.");
      }
      if (!decision || decision.decision !== "allow") {
        throw new Error("CodeGuard: " + (decision?.reason || "Inspector did not allow execution."));
      }
    },
  };
}
