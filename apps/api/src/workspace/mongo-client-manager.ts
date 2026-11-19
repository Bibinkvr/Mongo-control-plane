import { createHash } from "node:crypto";
import { MongoClient, type Db, type MongoClientOptions } from "mongodb";

type ClientEntry = {
  key: string;
  client: MongoClient;
  connected: Promise<void>;
  leases: number;
  lastUsedAt: number;
  closing: boolean;
};

export type MongoClientManagerOptions = {
  maxClients?: number;
  idleTimeoutMs?: number;
  sweepIntervalMs?: number;
  factory?: (uri: string, options: MongoClientOptions) => MongoClient;
};

/**
 * Bounded process-local MongoDB client cache.
 *
 * Cache keys contain a one-way URI fingerprint, never the URI itself. A changed
 * credential creates a new pool; the old pool is closed after its active leases
 * finish and it becomes idle. Call close() after the HTTP server stops accepting
 * requests.
 */
export class MongoClientManager {
  private readonly entries = new Map<string, ClientEntry>();
  private readonly maxClients: number;
  private readonly idleTimeoutMs: number;
  private readonly factory: (uri: string, options: MongoClientOptions) => MongoClient;
  private readonly sweepTimer: NodeJS.Timeout;
  private closed = false;

  constructor(options: MongoClientManagerOptions = {}) {
    this.maxClients = options.maxClients ?? 100;
    this.idleTimeoutMs = options.idleTimeoutMs ?? 60_000;
    const sweepIntervalMs = options.sweepIntervalMs ?? 15_000;
    if (!Number.isInteger(this.maxClients) || this.maxClients < 1 || this.maxClients > 2_000) {
      throw new Error("MongoDB client cache maxClients must be between 1 and 2000.");
    }
    if (!Number.isInteger(this.idleTimeoutMs) || this.idleTimeoutMs < 1_000 || this.idleTimeoutMs > 3_600_000) {
      throw new Error("MongoDB client cache idleTimeoutMs must be between 1000 and 3600000.");
    }
    if (!Number.isInteger(sweepIntervalMs) || sweepIntervalMs < 250 || sweepIntervalMs > 60_000) {
      throw new Error("MongoDB client cache sweepIntervalMs must be between 250 and 60000.");
    }
    this.factory = options.factory ?? ((uri, clientOptions) => new MongoClient(uri, clientOptions));
    this.sweepTimer = setInterval(() => { void this.sweepIdle(); }, sweepIntervalMs);
    this.sweepTimer.unref();
  }

  async withDatabase<T>(
    identity: string,
    uri: string,
    clientOptions: MongoClientOptions,
    databaseName: string,
    operation: (database: Db) => Promise<T>,
  ): Promise<T> {
    if (this.closed) throw new Error("MongoDB client manager is closed.");
    if (!identity || identity.length > 256 || !uri || !databaseName) {
      throw new Error("MongoDB client identity, URI, and database name are required.");
    }
    const fingerprint = createHash("sha256").update(uri, "utf8").digest("hex");
    const key = identity + ":" + fingerprint;
    let entry = this.entries.get(key);
    if (!entry) {
      await this.makeRoom();
      if (this.entries.size >= this.maxClients) {
        throw new Error("MongoDB client capacity is temporarily exhausted.");
      }
      const client = this.factory(uri, clientOptions);
      entry = {
        key,
        client,
        connected: Promise.resolve().then(() => client.connect()).then(() => undefined),
        leases: 0,
        lastUsedAt: Date.now(),
        closing: false,
      };
      this.entries.set(key, entry);
      void entry.connected.catch(async () => {
        if (this.entries.get(key) === entry) this.entries.delete(key);
        entry!.closing = true;
        await client.close().catch(() => undefined);
      });
    }

    entry.leases += 1;
    try {
      await entry.connected;
      if (this.closed) throw new Error("MongoDB client manager is shutting down.");
      entry.lastUsedAt = Date.now();
      return await operation(entry.client.db(databaseName));
    } finally {
      entry.leases = Math.max(0, entry.leases - 1);
      entry.lastUsedAt = Date.now();
    }
  }

  async sweepIdle(now = Date.now()): Promise<void> {
    const expired = [...this.entries.values()].filter(
      (entry) => entry.leases === 0 && !entry.closing && now - entry.lastUsedAt >= this.idleTimeoutMs,
    );
    await Promise.all(expired.map((entry) => this.closeEntry(entry)));
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this.sweepTimer);
    await Promise.all([...this.entries.values()].map((entry) => this.closeEntry(entry)));
  }

  get size(): number {
    return this.entries.size;
  }

  private async makeRoom(): Promise<void> {
    if (this.entries.size < this.maxClients) return;
    const idle = [...this.entries.values()]
      .filter((entry) => entry.leases === 0 && !entry.closing)
      .sort((a, b) => a.lastUsedAt - b.lastUsedAt);
    for (const entry of idle) {
      await this.closeEntry(entry);
      if (this.entries.size < this.maxClients) return;
    }
  }

  private async closeEntry(entry: ClientEntry): Promise<void> {
    if (entry.closing || entry.leases > 0) return;
    entry.closing = true;
    if (this.entries.get(entry.key) === entry) this.entries.delete(entry.key);
    await entry.connected.catch(() => undefined);
    await entry.client.close().catch(() => undefined);
  }
}
