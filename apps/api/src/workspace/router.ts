import { Router, type Request, type Response, type NextFunction } from "express";
import { MongoServerError, ObjectId } from "mongodb";
import { z } from "zod";
import type { Pool } from "pg";
import { resolveSession } from "../auth/router.js";
import { ConnectionCredentialError } from "../connections/credential-service.js";
import type { EncryptionKeyring } from "../connections/crypto.js";
import { DatabaseWorkspaceError, isSafeCollectionName, isSafeDocument, withManagedDatabase, type WorkspacePolicy } from "./service.js";

const MAX_DOCUMENT_BYTES = 1_000_000;
const MAX_RESPONSE_BYTES = 2_000_000;

function jsonByteLength(value: unknown): number {
  const serialized = JSON.stringify(value);
  return typeof serialized === "string" ? Buffer.byteLength(serialized, "utf8") : Number.MAX_SAFE_INTEGER;
}
const collectionNameSchema = z.string().min(1).max(120).refine(isSafeCollectionName);

function sendWorkspaceError(error: unknown, response: Response, next: NextFunction): void {
  if (error instanceof DatabaseWorkspaceError || error instanceof ConnectionCredentialError) {
    const status = error.code === "PROJECT_NOT_FOUND" || error.code === "DATABASE_NOT_FOUND" || error.code === "CONNECTION_NOT_FOUND" ? 404
      : error.code === "FORBIDDEN" ? 403
      : error.code === "DATABASE_NOT_READY" || error.code === "CONNECTION_DISABLED" ? 409 : 400;
    response.status(status).json({ error: { code: error.code, message: error.message } });
    return;
  }
  if (error instanceof MongoServerError) {
    if (error.code === 48 || error.code === 11000) {
      response.status(409).json({ error: { code: "CONFLICT", message: "The requested MongoDB resource already exists." } });
      return;
    }
    if (error.code === 26 || error.code === 27) {
      response.status(404).json({ error: { code: "MONGODB_RESOURCE_NOT_FOUND", message: "The requested MongoDB resource was not found." } });
      return;
    }
  }
  next(error);
}

function parseIds(request: Request, response: Response): { projectId: string; databaseId: string } | undefined {
  const projectId = z.string().uuid().safeParse(request.params["projectId"]);
  const databaseId = z.string().uuid().safeParse(request.params["databaseId"]);
  if (!projectId.success || !databaseId.success) {
    response.status(400).json({ error: { code: "INVALID_ID", message: "A project or database ID is invalid." } });
    return undefined;
  }
  return { projectId: projectId.data, databaseId: databaseId.data };
}

function validDocument(document: unknown): document is Record<string, unknown> {
  if (!isSafeDocument(document)) return false;
  if (Object.prototype.hasOwnProperty.call(document, "_id")) return false;
  return Buffer.byteLength(JSON.stringify(document), "utf8") <= MAX_DOCUMENT_BYTES;
}

export function createWorkspaceRouter(pool: Pool, keyring: EncryptionKeyring, policy: WorkspacePolicy = {}): Router {
  const router = Router();
  router.use((_request, response, next) => { response.setHeader("Cache-Control", "no-store"); next(); });
  router.use(async (request: Request, response: Response, next: NextFunction) => {
    try {
      const user = await resolveSession(pool, request);
      if (!user) {
        response.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Authentication is required." } });
        return;
      }
      response.locals["workspaceCaller"] = { userId: user.id, isPlatformAdmin: user.is_platform_admin };
      next();
    } catch (error) { next(error); }
  });

  router.get("/:projectId/databases/:databaseId/collections", async (request, response, next) => {
    const ids = parseIds(request, response);
    if (!ids) return;
    try {
      const collections = await withManagedDatabase(pool, keyring, policy, {
        caller: response.locals["workspaceCaller"] as { userId: string; isPlatformAdmin: boolean },
        ...ids, permission: "database:read",
      }, async (database) => database.listCollections({}, { nameOnly: true }).toArray());
      response.status(200).json({ collections: collections.map((item) => ({ name: item.name, type: item.type })) });
    } catch (error) { sendWorkspaceError(error, response, next); }
  });

  router.post("/:projectId/databases/:databaseId/collections", async (request, response, next) => {
    const ids = parseIds(request, response);
    const body = z.object({ name: collectionNameSchema }).strict().safeParse(request.body);
    if (!ids) return;
    if (!body.success) {
      response.status(400).json({ error: { code: "INVALID_COLLECTION_NAME", message: "Provide a valid collection name." } });
      return;
    }
    try {
      await withManagedDatabase(pool, keyring, policy, {
        caller: response.locals["workspaceCaller"] as { userId: string; isPlatformAdmin: boolean },
        ...ids, permission: "database:admin", auditAction: "database.collection.create",
        auditMetadata: { collection: body.data.name },
      }, async (database) => database.createCollection(body.data.name));
      response.status(201).json({ collection: { name: body.data.name } });
    } catch (error) { sendWorkspaceError(error, response, next); }
  });

  router.delete("/:projectId/databases/:databaseId/collections/:collectionName", async (request, response, next) => {
    const ids = parseIds(request, response);
    const name = collectionNameSchema.safeParse(request.params["collectionName"]);
    const body = z.object({ confirmCollectionName: z.string().min(1).max(120) }).strict().safeParse(request.body);
    if (!ids) return;
    if (!name.success || !body.success || body.data.confirmCollectionName !== name.data) {
      response.status(400).json({ error: { code: "CONFIRMATION_REQUIRED", message: "Confirm the exact collection name before deletion." } });
      return;
    }
    try {
      const dropped = await withManagedDatabase(pool, keyring, policy, {
        caller: response.locals["workspaceCaller"] as { userId: string; isPlatformAdmin: boolean },
        ...ids, permission: "database:admin", auditAction: "database.collection.drop",
        auditMetadata: { collection: name.data },
      }, async (database) => database.dropCollection(name.data));
      if (!dropped) {
        response.status(404).json({ error: { code: "COLLECTION_NOT_FOUND", message: "The collection was not found." } });
        return;
      }
      response.status(200).json({ dropped: true, collection: name.data });
    } catch (error) { sendWorkspaceError(error, response, next); }
  });

  router.get("/:projectId/databases/:databaseId/collections/:collectionName/documents", async (request, response, next) => {
    const ids = parseIds(request, response);
    const name = collectionNameSchema.safeParse(request.params["collectionName"]);
    const pagination = z.object({
      limit: z.coerce.number().int().min(1).max(100).default(25),
      skip: z.coerce.number().int().min(0).max(10_000).default(0),
    }).safeParse(request.query);
    if (!ids) return;
    if (!name.success || !pagination.success) {
      response.status(400).json({ error: { code: "INVALID_QUERY", message: "Collection name or pagination parameters are invalid." } });
      return;
    }
    try {
      const documents = await withManagedDatabase(pool, keyring, policy, {
        caller: response.locals["workspaceCaller"] as { userId: string; isPlatformAdmin: boolean },
        ...ids, permission: "database:read",
      }, async (database) => database.collection(name.data)
        .find({}, { maxTimeMS: 5_000 })
        .sort({ _id: 1 })
        .skip(pagination.data.skip)
        .limit(pagination.data.limit)
        .toArray());
      if (jsonByteLength(documents) > MAX_RESPONSE_BYTES) {
        response.status(413).json({ error: { code: "RESPONSE_TOO_LARGE", message: "Reduce the page size to retrieve these documents." } });
        return;
      }
      response.status(200).json({ documents, limit: pagination.data.limit, skip: pagination.data.skip });
    } catch (error) { sendWorkspaceError(error, response, next); }
  });

  router.post("/:projectId/databases/:databaseId/collections/:collectionName/documents", async (request, response, next) => {
    const ids = parseIds(request, response);
    const name = collectionNameSchema.safeParse(request.params["collectionName"]);
    if (!ids) return;
    if (!name.success || !validDocument(request.body)) {
      response.status(400).json({ error: { code: "INVALID_DOCUMENT", message: "Provide a safe JSON document without a custom _id." } });
      return;
    }
    try {
      const insertedId = await withManagedDatabase(pool, keyring, policy, {
        caller: response.locals["workspaceCaller"] as { userId: string; isPlatformAdmin: boolean },
        ...ids, permission: "database:write", auditAction: "database.document.insert",
        auditMetadata: { collection: name.data },
      }, async (database) => {
        const result = await database.collection(name.data).insertOne(request.body as Record<string, unknown>);
        return result.insertedId.toString();
      });
      response.status(201).json({ insertedId });
    } catch (error) { sendWorkspaceError(error, response, next); }
  });

  router.patch("/:projectId/databases/:databaseId/collections/:collectionName/documents/:documentId", async (request, response, next) => {
    const ids = parseIds(request, response);
    const name = collectionNameSchema.safeParse(request.params["collectionName"]);
    const documentId = z.string().regex(/^[a-f\d]{24}$/i).safeParse(request.params["documentId"]);
    const body = z.object({ set: z.record(z.string(), z.unknown()) }).strict().safeParse(request.body);
    if (!ids) return;
    if (!name.success || !documentId.success || !body.success
      || Object.keys(body.data.set).length === 0
      || Object.prototype.hasOwnProperty.call(body.data.set, "_id")
      || !isSafeDocument(body.data.set)
      || jsonByteLength(body.data.set) > MAX_DOCUMENT_BYTES) {
      response.status(400).json({ error: { code: "INVALID_UPDATE", message: "Provide safe fields to update; _id and MongoDB operators are not allowed." } });
      return;
    }
    try {
      const result = await withManagedDatabase(pool, keyring, policy, {
        caller: response.locals["workspaceCaller"] as { userId: string; isPlatformAdmin: boolean },
        ...ids, permission: "database:write", auditAction: "database.document.update",
        auditMetadata: { collection: name.data },
      }, async (database) => database.collection(name.data).updateOne(
        { _id: new ObjectId(documentId.data) },
        { $set: body.data.set },
        { maxTimeMS: 5_000 },
      ));
      if (result.matchedCount === 0) {
        response.status(404).json({ error: { code: "DOCUMENT_NOT_FOUND", message: "The document was not found." } });
        return;
      }
      response.status(200).json({ matchedCount: result.matchedCount, modifiedCount: result.modifiedCount });
    } catch (error) { sendWorkspaceError(error, response, next); }
  });

  router.delete("/:projectId/databases/:databaseId/collections/:collectionName/documents/:documentId", async (request, response, next) => {
    const ids = parseIds(request, response);
    const name = collectionNameSchema.safeParse(request.params["collectionName"]);
    const documentId = z.string().regex(/^[a-f\d]{24}$/i).safeParse(request.params["documentId"]);
    if (!ids) return;
    if (!name.success || !documentId.success) {
      response.status(400).json({ error: { code: "INVALID_DOCUMENT_ID", message: "A valid collection and ObjectId are required." } });
      return;
    }
    try {
      const result = await withManagedDatabase(pool, keyring, policy, {
        caller: response.locals["workspaceCaller"] as { userId: string; isPlatformAdmin: boolean },
        ...ids, permission: "database:write", auditAction: "database.document.delete",
        auditMetadata: { collection: name.data },
      }, async (database) => database.collection(name.data).deleteOne(
        { _id: new ObjectId(documentId.data) },
        { maxTimeMS: 5_000 },
      ));
      if (result.deletedCount === 0) {
        response.status(404).json({ error: { code: "DOCUMENT_NOT_FOUND", message: "The document was not found." } });
        return;
      }
      response.status(200).json({ deletedCount: result.deletedCount });
    } catch (error) { sendWorkspaceError(error, response, next); }
  });

  router.get("/:projectId/databases/:databaseId/collections/:collectionName/indexes", async (request, response, next) => {
    const ids = parseIds(request, response);
    const name = collectionNameSchema.safeParse(request.params["collectionName"]);
    if (!ids) return;
    if (!name.success) {
      response.status(400).json({ error: { code: "INVALID_COLLECTION_NAME", message: "Provide a valid collection name." } });
      return;
    }
    try {
      const indexes = await withManagedDatabase(pool, keyring, policy, {
        caller: response.locals["workspaceCaller"] as { userId: string; isPlatformAdmin: boolean },
        ...ids, permission: "database:read",
      }, async (database) => database.collection(name.data).listIndexes().toArray());
      response.status(200).json({ indexes });
    } catch (error) { sendWorkspaceError(error, response, next); }
  });

  router.post("/:projectId/databases/:databaseId/collections/:collectionName/indexes", async (request, response, next) => {
    const ids = parseIds(request, response);
    const name = collectionNameSchema.safeParse(request.params["collectionName"]);
    const body = z.object({
      keys: z.record(z.string(), z.union([z.literal(1), z.literal(-1)])),
      unique: z.boolean().optional(),
    }).strict().safeParse(request.body);
    if (!ids) return;
    const keys = body.success ? body.data.keys : {};
    const safeKeys = Object.keys(keys).length > 0 && Object.keys(keys).length <= 8
      && Object.keys(keys).every((key) => key.length <= 120 && !key.startsWith("$") && !key.includes("."));
    if (!name.success || !body.success || !safeKeys) {
      response.status(400).json({ error: { code: "INVALID_INDEX", message: "Provide one to eight valid index fields with direction 1 or -1." } });
      return;
    }
    try {
      const indexName = await withManagedDatabase(pool, keyring, policy, {
        caller: response.locals["workspaceCaller"] as { userId: string; isPlatformAdmin: boolean },
        ...ids, permission: "database:admin", auditAction: "database.index.create",
        auditMetadata: { collection: name.data, fields: Object.keys(keys) },
      }, async (database) => database.collection(name.data).createIndex(keys, { unique: body.data.unique ?? false }));
      response.status(201).json({ indexName });
    } catch (error) { sendWorkspaceError(error, response, next); }
  });

  router.delete("/:projectId/databases/:databaseId/collections/:collectionName/indexes/:indexName", async (request, response, next) => {
    const ids = parseIds(request, response);
    const name = collectionNameSchema.safeParse(request.params["collectionName"]);
    const indexName = z.string().min(1).max(120).safeParse(request.params["indexName"]);
    if (!ids) return;
    if (!name.success || !indexName.success || indexName.data === "_id_") {
      response.status(400).json({ error: { code: "INVALID_INDEX", message: "A valid non-_id_ index name is required." } });
      return;
    }
    try {
      await withManagedDatabase(pool, keyring, policy, {
        caller: response.locals["workspaceCaller"] as { userId: string; isPlatformAdmin: boolean },
        ...ids, permission: "database:admin", auditAction: "database.index.drop",
        auditMetadata: { collection: name.data, indexName: indexName.data },
      }, async (database) => database.collection(name.data).dropIndex(indexName.data));
      response.status(200).json({ dropped: true, indexName: indexName.data });
    } catch (error) { sendWorkspaceError(error, response, next); }
  });

  return router;
}
