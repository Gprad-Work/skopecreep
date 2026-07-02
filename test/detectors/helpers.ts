import { emptyInventory } from "../../dist/model.js";
import type { Inventory, SourceRef } from "../../dist/model.js";

export function inv(overrides: Partial<Inventory>): Inventory {
  return { ...emptyInventory(), ...overrides };
}

export function src(path: string, locator?: string): SourceRef {
  return locator === undefined ? { path } : { path, locator };
}
