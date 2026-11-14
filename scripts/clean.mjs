// Removes dist/ before a build, so a deleted source file never ships from a stale build.
import { rmSync } from "node:fs";

rmSync(new URL("../dist", import.meta.url), { recursive: true, force: true });
