import type { Inventory } from "../model.js";

export interface CollectorContext {
  /** user home directory */
  home: string;
  /** project root to scan for project-scoped config (cwd or --path) */
  projectPath: string;
}

export type Collector = (ctx: CollectorContext, inv: Inventory) => void;
