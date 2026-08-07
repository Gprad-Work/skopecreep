/**
 * Recognize non-agent AI systems on the machine — local model runtimes, model
 * hubs, and API clients — read-only (no execution, no network). Presence is
 * inventory; the risk signals it records (plaintext token files, a runtime
 * bound to a non-loopback address) are what detectAiRuntimes turns into
 * findings. Env-var API keys are inventory-only: an env var is the recommended
 * place for a key, so flagging it would be miscalibrated.
 */
import * as path from "node:path";
import type { AIRuntime, AIRuntimeKind } from "../model.js";
import { fileExists, IS_WINDOWS } from "../util.js";
import type { Collector } from "./types.js";

interface RuntimeSpec {
  id: string;
  displayName: string;
  kind: AIRuntimeKind;
  /** home-relative dirs/files whose existence proves presence */
  paths?: string[];
  /** binaries to look for on PATH (never executed) */
  bins?: string[];
  /** env vars whose presence proves the runtime is configured here */
  envVars?: string[];
  /** home-relative files that hold a plaintext token when present */
  tokenFiles?: string[];
  /** env var (e.g. OLLAMA_HOST) whose non-loopback value means it listens off-host */
  exposedEnv?: string;
}

const REGISTRY: RuntimeSpec[] = [
  // Local model runtimes
  {
    id: "ollama",
    displayName: "Ollama",
    kind: "local-runtime",
    paths: ["~/.ollama"],
    bins: ["ollama"],
    exposedEnv: "OLLAMA_HOST",
  },
  {
    id: "lm-studio",
    displayName: "LM Studio",
    kind: "local-runtime",
    paths: ["~/.lmstudio", "~/.cache/lm-studio", "~/Library/Application Support/LM Studio"],
    bins: ["lms"],
  },
  {
    id: "llama-cpp",
    displayName: "llama.cpp",
    kind: "local-runtime",
    paths: ["~/.cache/llama.cpp"],
    bins: ["llama-server", "llama-cli"],
  },
  {
    id: "gpt4all",
    displayName: "GPT4All",
    kind: "local-runtime",
    paths: ["~/.cache/gpt4all", "~/Library/Application Support/nomic.ai/GPT4All", "~/AppData/Roaming/nomic.ai/GPT4All"],
  },
  { id: "vllm", displayName: "vLLM", kind: "local-runtime", bins: ["vllm"] },
  {
    id: "text-generation-webui",
    displayName: "Text Generation WebUI",
    kind: "local-runtime",
    paths: ["~/text-generation-webui"],
  },
  // Model hubs
  {
    id: "huggingface",
    displayName: "Hugging Face",
    kind: "model-hub",
    paths: ["~/.cache/huggingface", "~/.huggingface"],
    bins: ["huggingface-cli", "hf"],
    envVars: ["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_TOKEN"],
    tokenFiles: ["~/.huggingface/token", "~/.cache/huggingface/token"],
  },
  // API clients (env-var presence is inventory-only)
  {
    id: "deepseek",
    displayName: "DeepSeek",
    kind: "api-client",
    paths: ["~/.deepseek"],
    envVars: ["DEEPSEEK_API_KEY"],
  },
  { id: "openai", displayName: "OpenAI", kind: "api-client", bins: ["openai"], envVars: ["OPENAI_API_KEY"] },
  { id: "anthropic-api", displayName: "Anthropic API", kind: "api-client", envVars: ["ANTHROPIC_API_KEY"] },
  { id: "together", displayName: "Together AI", kind: "api-client", envVars: ["TOGETHER_API_KEY"] },
  { id: "groq", displayName: "Groq", kind: "api-client", envVars: ["GROQ_API_KEY"] },
  { id: "mistral", displayName: "Mistral", kind: "api-client", envVars: ["MISTRAL_API_KEY"] },
];

/** Expand a leading `~` against the scan's home (not the process home — keeps tests hermetic). */
function underHome(home: string, p: string): string {
  return p.startsWith("~/") ? path.join(home, p.slice(2)) : p;
}

/** Is `bin` present on PATH? Read-only stat, never executed. */
function onPath(bin: string): string | null {
  const dirs = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  const names = IS_WINDOWS ? [bin, `${bin}.exe`, `${bin}.cmd`] : [bin];
  for (const dir of dirs) {
    for (const name of names) {
      const full = path.join(dir, name);
      if (fileExists(full)) return full;
    }
  }
  return null;
}

/** Host portion of an OLLAMA_HOST-style value, or "" if it's loopback/empty. */
function nonLoopbackHost(raw: string): string {
  let v = raw.trim();
  if (!v) return "";
  v = v.replace(/^https?:\/\//, "");
  const host = v
    .split("/")[0]!
    .replace(/:\d+$/, "")
    .replace(/^\[|\]$/g, "")
    .toLowerCase();
  if (!host) return "";
  if (host === "localhost" || host.endsWith(".localhost") || host.startsWith("127.") || host === "::1") return "";
  return host;
}

export const collectAiRuntimes: Collector = (ctx, inv) => {
  for (const spec of REGISTRY) {
    const evidence: string[] = [];
    const tokenFiles: string[] = [];

    for (const p of spec.paths ?? []) {
      const full = underHome(ctx.home, p);
      if (fileExists(full)) evidence.push(full);
    }
    for (const bin of spec.bins ?? []) {
      const hit = onPath(bin);
      if (hit) evidence.push(hit);
    }
    for (const env of spec.envVars ?? []) {
      if (process.env[env]) evidence.push(`$${env}`);
    }
    for (const tf of spec.tokenFiles ?? []) {
      const full = underHome(ctx.home, tf);
      if (fileExists(full)) {
        evidence.push(full);
        tokenFiles.push(full);
      }
    }

    let exposedHost: string | undefined;
    if (spec.exposedEnv && process.env[spec.exposedEnv]) {
      const host = nonLoopbackHost(process.env[spec.exposedEnv]!);
      if (host) {
        exposedHost = host;
        evidence.push(`$${spec.exposedEnv}=${process.env[spec.exposedEnv]}`);
      }
    }

    if (evidence.length === 0) continue;

    const runtime: AIRuntime = {
      id: spec.id,
      displayName: spec.displayName,
      kind: spec.kind,
      installed: true,
      evidence,
    };
    if (tokenFiles.length > 0) runtime.tokenFiles = tokenFiles;
    if (exposedHost) runtime.exposedHost = exposedHost;
    inv.aiRuntimes.push(runtime);
  }
};
