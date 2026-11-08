// In-memory storage. Used by the tests; state is lost when the process stops.

export class MemoryStore {
  constructor(initial = null) {
    this.value = initial;
  }

  async read() {
    return this.value === null ? null : structuredClone(this.value);
  }

  async write(value) {
    this.value = structuredClone(value);
  }
}
