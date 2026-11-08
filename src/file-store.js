// Saves state to one JSON file. Writes go to a temporary file first, then
// replace the old file, so a crash mid-write can't leave a half-written file.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export class FileStore {
  constructor(path) {
    this.path = path;
  }

  async read() {
    try {
      return JSON.parse(await readFile(this.path, "utf8"));
    } catch (err) {
      if (err.code === "ENOENT") return null;
      throw err;
    }
  }

  async write(value) {
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify(value, null, 2));
    await rename(tmp, this.path);
  }
}
