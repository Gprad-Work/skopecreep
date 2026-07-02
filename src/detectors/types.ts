import type { Finding, Inventory } from "../model.js";

export type Detector = (inv: Inventory) => Finding[];
