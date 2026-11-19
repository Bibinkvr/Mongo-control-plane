import { afterEach, describe, expect, it, vi } from "vitest";
import type { Db, MongoClient, MongoClientOptions } from "mongodb";
import { MongoClientManager } from "../src/workspace/mongo-client-manager.js";

function fakeClient() {
  const database = {} as Db;
  const client = {
    connect: vi.fn().mockResolvedValue(undefined),
    db: vi.fn().mockReturnValue(database),
    close: vi.fn().mockResolvedValue(undefined),
  } as unknown as MongoClient;
  return { client, database };
}

const options: MongoClientOptions = {};

describe("MongoClientManager", () => {
  const managers: MongoClientManager[] = [];
  afterEach(async () => {
    await Promise.all(managers.splice(0).map((manager) => manager.close()));
  });

  it("reuses a pool for the same database credential and replaces it when credentials rotate", async () => {
    const created: ReturnType<typeof fakeClient>[] = [];
    const manager = new MongoClientManager({
      factory: () => {
        const item = fakeClient();
        created.push(item);
        return item.client;
      },
    });
    managers.push(manager);

    const first = await manager.withDatabase("resource-1", "mongodb://user:one@db.example.com/app", options, "app", async () => "first");
    const second = await manager.withDatabase("resource-1", "mongodb://user:one@db.example.com/app", options, "app", async () => "second");
    const rotated = await manager.withDatabase("resource-1", "mongodb://user:two@db.example.com/app", options, "app", async () => "rotated");

    expect([first, second, rotated]).toEqual(["first", "second", "rotated"]);
    expect(created).toHaveLength(2);
    expect(created[0]!.client.connect).toHaveBeenCalledTimes(1);
    expect(created[0]!.client.db).toHaveBeenCalledTimes(2);
    expect(manager.size).toBe(2);
  });

  it("retires an old credential pool after its active operation finishes", async () => {
    const created: ReturnType<typeof fakeClient>[] = [];
    const manager = new MongoClientManager({
      factory: () => {
        const item = fakeClient();
        created.push(item);
        return item.client;
      },
    });
    managers.push(manager);

    let finishOldOperation!: () => void;
    let markOldEntered!: () => void;
    const oldGate = new Promise<void>((resolve) => { finishOldOperation = resolve; });
    const oldEntered = new Promise<void>((resolve) => { markOldEntered = resolve; });
    const oldOperation = manager.withDatabase(
      "resource-1",
      "mongodb://user:old@db.example.com/app",
      options,
      "app",
      async () => { markOldEntered(); return oldGate; },
    );
    await oldEntered;

    await manager.withDatabase(
      "resource-1",
      "mongodb://user:new@db.example.com/app",
      options,
      "app",
      async () => undefined,
    );
    expect(created).toHaveLength(2);
    expect(created[0]!.client.close).not.toHaveBeenCalled();

    finishOldOperation();
    await oldOperation;
    await vi.waitFor(() => expect(created[0]!.client.close).toHaveBeenCalledTimes(1));
    expect(created[1]!.client.close).not.toHaveBeenCalled();
  });

  it("closes idle pools after the configured idle timeout", async () => {
    const item = fakeClient();
    const manager = new MongoClientManager({ factory: () => item.client, idleTimeoutMs: 1_000 });
    managers.push(manager);

    await manager.withDatabase("resource-1", "mongodb://user:one@db.example.com/app", options, "app", async () => undefined);
    await manager.sweepIdle(Date.now() + 2_000);

    expect(item.client.close).toHaveBeenCalledTimes(1);
    expect(manager.size).toBe(0);
  });

  it("waits for active operations before closing pools during shutdown", async () => {
    const item = fakeClient();
    const manager = new MongoClientManager({ factory: () => item.client });
    managers.push(manager);

    let finishOperation!: () => void;
    let markEntered!: () => void;
    const operationGate = new Promise<void>((resolve) => { finishOperation = resolve; });
    const entered = new Promise<void>((resolve) => { markEntered = resolve; });
    const operation = manager.withDatabase(
      "resource-1",
      "mongodb://user:one@db.example.com/app",
      options,
      "app",
      async () => { markEntered(); return operationGate; },
    );
    await entered;

    let closeFinished = false;
    const closing = manager.close().then(() => { closeFinished = true; });
    await Promise.resolve();
    expect(closeFinished).toBe(false);
    expect(item.client.close).not.toHaveBeenCalled();

    finishOperation();
    await operation;
    await closing;
    expect(item.client.close).toHaveBeenCalledTimes(1);
    expect(closeFinished).toBe(true);
  });

  it("rejects new pools when every cache slot is actively leased", async () => {
    const created: ReturnType<typeof fakeClient>[] = [];
    const manager = new MongoClientManager({
      maxClients: 1,
      factory: () => {
        const item = fakeClient();
        created.push(item);
        return item.client;
      },
    });
    managers.push(manager);

    let finishOperation!: () => void;
    let markEntered!: () => void;
    const gate = new Promise<void>((resolve) => { finishOperation = resolve; });
    const entered = new Promise<void>((resolve) => { markEntered = resolve; });
    const active = manager.withDatabase(
      "resource-1",
      "mongodb://user:one@db.example.com/app",
      options,
      "app",
      async () => { markEntered(); return gate; },
    );
    await entered;

    await expect(manager.withDatabase(
      "resource-2",
      "mongodb://user:two@db.example.com/app",
      options,
      "app",
      async () => undefined,
    )).rejects.toThrow(/capacity/);

    finishOperation();
    await active;
    expect(created).toHaveLength(1);
  });
});
