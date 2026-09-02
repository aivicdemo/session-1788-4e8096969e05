import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  ScanCommand,
  QueryCommand,
  BatchWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'crypto';
import {
  extractAuthContext,
  requirePermission,
  ForbiddenError,
  NotFoundError,
  ValidationError,
} from './rbac';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE || 'PublicFacilityDB';

interface AuditLog {
  pk: string;
  sk: string;
  userId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  timestamp: number;
  details: Record<string, unknown>;
}

interface Resource {
  id: string;
  name: string;
  description?: string;
  type: string;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
  [key: string]: unknown;
}

const TABLE_INDICES: Record<number, string> = {
  0: 'users',
  1: 'facilities',
  2: 'timeslots',
  3: 'reservations',
  4: 'lotteries',
  5: 'payments',
  6: 'paymenthistory',
  7: 'cancellations',
  8: 'categories',
  9: 'authlogs',
  10: 'auditlogs',
};

function getTableKey(tableIndex: number): string {
  return TABLE_INDICES[tableIndex] || 'unknown';
}

async function createAuditLog(
  userId: string,
  action: string,
  resourceType: string,
  resourceId: string,
  details: Record<string, unknown>
): Promise<void> {
  const auditLog: AuditLog = {
    pk: 'AUDIT',
    sk: `${Date.now()}#${randomUUID()}`,
    userId,
    action,
    resourceType,
    resourceId,
    timestamp: Date.now(),
    details,
  };

  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: auditLog,
    })
  );
}

function validateResource(resource: Record<string, unknown>, requiredFields: string[]): void {
  for (const field of requiredFields) {
    if (resource[field] === undefined || resource[field] === null) {
      throw new ValidationError(`Missing required field: ${field}`);
    }
  }
}

function errorResponse(statusCode: number, message: string): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify({ error: message }),
    headers: { 'Content-Type': 'application/json' },
  };
}

function successResponse(statusCode: number, data: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify(data),
    headers: { 'Content-Type': 'application/json' },
  };
}

// GET /resources
export async function getResources(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    requirePermission(context, 'resources:read');

    const result = await docClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
        FilterExpression: 'attribute_exists(id)',
      })
    );

    return successResponse(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error fetching resources:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// GET /resources/{id}
export async function getResourceById(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    requirePermission(context, 'resources:read');

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'Missing resource ID');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    if (!result.Item) {
      return errorResponse(404, 'Resource not found');
    }

    return successResponse(200, result.Item);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error fetching resource:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /resources
export async function createResource(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    requirePermission(context, 'resources:create');

    const body = JSON.parse(event.body || '{}');
    validateResource(body, ['name', 'type']);

    const resource: Resource = {
      id: randomUUID(),
      name: body.name,
      description: body.description,
      type: body.type,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      createdBy: context.userId,
      ...body,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: resource,
      })
    );

    await createAuditLog(
      context.userId,
      'CREATE',
      'resource',
      resource.id,
      { resource }
    );

    return successResponse(201, resource);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    if (error instanceof ValidationError) {
      return errorResponse(400, error.message);
    }
    console.error('Error creating resource:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// PUT /resources/{id}
export async function updateResource(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    requirePermission(context, 'resources:update');

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'Missing resource ID');
    }

    const body = JSON.parse(event.body || '{}');

    const existing = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    if (!existing.Item) {
      return errorResponse(404, 'Resource not found');
    }

    const updated = {
      ...existing.Item,
      ...body,
      id,
      updatedAt: Date.now(),
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: updated,
      })
    );

    await createAuditLog(
      context.userId,
      'UPDATE',
      'resource',
      id,
      { before: existing.Item, after: updated }
    );

    return successResponse(200, updated);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error updating resource:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// DELETE /resources/{id}
export async function deleteResource(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    requirePermission(context, 'resources:delete');

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'Missing resource ID');
    }

    const existing = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    if (!existing.Item) {
      return errorResponse(404, 'Resource not found');
    }

    await docClient.send(
      new DeleteCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    await createAuditLog(
      context.userId,
      'DELETE',
      'resource',
      id,
      { deleted: existing.Item }
    );

    return successResponse(204, null);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error deleting resource:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/{tableIndex}/bulk
export async function bulkImport(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    requirePermission(context, 'resources:bulk');

    const tableIndex = parseInt(event.pathParameters?.tableIndex || '0', 10);
    const tableKey = getTableKey(tableIndex);

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'Items must be an array');
    }

    if (items.length === 0) {
      return successResponse(200, { imported: 0, failed: 0, errors: [] });
    }

    const enrichedItems = items.map((item: Record<string, unknown>) => ({
      ...item,
      id: item.id || randomUUID(),
      createdAt: item.createdAt || Date.now(),
      updatedAt: item.updatedAt || Date.now(),
      createdBy: context.userId,
    }));

    const chunks = [];
    for (let i = 0; i < enrichedItems.length; i += 25) {
      chunks.push(enrichedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      const requestItems = chunk.map((item) => ({
        PutRequest: {
          Item: item,
        },
      }));

      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: requestItems,
            },
          })
        );
        imported += chunk.length;
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        errors.push(`Batch write failed: ${errorMsg}`);
      }
    }

    await createAuditLog(
      context.userId,
      'BULK_IMPORT',
      tableKey,
      'bulk',
      { itemCount: imported, tableKey }
    );

    return successResponse(200, {
      imported,
      failed: items.length - imported,
      errors,
    });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    if (error instanceof ValidationError) {
      return errorResponse(400, error.message);
    }
    console.error('Error in bulk import:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// GET /api/{tableIndex}
export async function getTableItems(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    const tableIndex = parseInt(event.pathParameters?.tableIndex || '0', 10);
    const tableKey = getTableKey(tableIndex);
    requirePermission(context, `${tableKey}:read`);

    const result = await docClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
        FilterExpression: 'attribute_exists(id)',
      })
    );

    return successResponse(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error fetching table items:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// GET /api/{tableIndex}/{id}
export async function getTableItemById(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    const tableIndex = parseInt(event.pathParameters?.tableIndex || '0', 10);
    const tableKey = getTableKey(tableIndex);
    requirePermission(context, `${tableKey}:read`);

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'Missing item ID');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    if (!result.Item) {
      return errorResponse(404, 'Item not found');
    }

    return successResponse(200, result.Item);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error fetching item:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/{tableIndex}
export async function createTableItem(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    const tableIndex = parseInt(event.pathParameters?.tableIndex || '0', 10);
    const tableKey = getTableKey(tableIndex);
    requirePermission(context, `${tableKey}:create`);

    const body = JSON.parse(event.body || '{}');

    const item: Resource = {
      id: randomUUID(),
      createdAt: Date.now(),
      updatedAt: Date.now(),
      createdBy: context.userId,
      ...body,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(
      context.userId,
      'CREATE',
      tableKey,
      item.id,
      { item }
    );

    return successResponse(201, item);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    if (error instanceof ValidationError) {
      return errorResponse(400, error.message);
    }
    console.error('Error creating item:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// PUT /api/{tableIndex}/{id}
export async function updateTableItem(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    const tableIndex = parseInt(event.pathParameters?.tableIndex || '0', 10);
    const tableKey = getTableKey(tableIndex);
    requirePermission(context, `${tableKey}:update`);

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'Missing item ID');
    }

    const body = JSON.parse(event.body || '{}');

    const existing = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    if (!existing.Item) {
      return errorResponse(404, 'Item not found');
    }

    const updated = {
      ...existing.Item,
      ...body,
      id,
      updatedAt: Date.now(),
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: updated,
      })
    );

    await createAuditLog(
      context.userId,
      'UPDATE',
      tableKey,
      id,
      { before: existing.Item, after: updated }
    );

    return successResponse(200, updated);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error updating item:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// DELETE /api/{tableIndex}/{id}
export async function deleteTableItem(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    const tableIndex = parseInt(event.pathParameters?.tableIndex || '0', 10);
    const tableKey = getTableKey(tableIndex);
    requirePermission(context, `${tableKey}:delete`);

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'Missing item ID');
    }

    const existing = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    if (!existing.Item) {
      return errorResponse(404, 'Item not found');
    }

    await docClient.send(
      new DeleteCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    await createAuditLog(
      context.userId,
      'DELETE',
      tableKey,
      id,
      { deleted: existing.Item }
    );

    return successResponse(204, null);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error deleting item:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// Lambda handler router
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const path = event.path || '';
  const method = event.httpMethod || 'GET';

  console.log(`${method} ${path}`);

  try {
    // GET /resources
    if (method === 'GET' && path === '/resources') {
      return await getResources(event);
    }

    // GET /resources/{id}
    if (method === 'GET' && path.match(/^\/resources\/[^/]+$/)) {
      return await getResourceById(event);
    }

    // POST /resources
    if (method === 'POST' && path === '/resources') {
      return await createResource(event);
    }

    // PUT /resources/{id}
    if (method === 'PUT' && path.match(/^\/resources\/[^/]+$/)) {
      return await updateResource(event);
    }

    // DELETE /resources/{id}
    if (method === 'DELETE' && path.match(/^\/resources\/[^/]+$/)) {
      return await deleteResource(event);
    }

    // POST /api/{tableIndex}/bulk
    if (method === 'POST' && path.match(/^\/api\/\d+\/bulk$/)) {
      return await bulkImport(event);
    }

    // GET /api/{tableIndex}
    if (method === 'GET' && path.match(/^\/api\/\d+$/) && !path.includes('bulk')) {
      return await getTableItems(event);
    }

    // GET /api/{tableIndex}/{id}
    if (method === 'GET' && path.match(/^\/api\/\d+\/[^/]+$/) && !path.includes('bulk')) {
      return await getTableItemById(event);
    }

    // POST /api/{tableIndex}
    if (method === 'POST' && path.match(/^\/api\/\d+$/) && !path.includes('bulk')) {
      return await createTableItem(event);
    }

    // PUT /api/{tableIndex}/{id}
    if (method === 'PUT' && path.match(/^\/api\/\d+\/[^/]+$/) && !path.includes('bulk')) {
      return await updateTableItem(event);
    }

    // DELETE /api/{tableIndex}/{id}
    if (method === 'DELETE' && path.match(/^\/api\/\d+\/[^/]+$/) && !path.includes('bulk')) {
      return await deleteTableItem(event);
    }

    return errorResponse(404, 'Not found');
  } catch (error) {
    console.error('Unhandled error:', error);
    return errorResponse(500, 'Internal server error');
  }
}