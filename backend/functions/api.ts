import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  BatchWriteItemCommandInput,
} from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  ScanCommand,
  GetCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'crypto';
import { extractRBACContext, requirePermission, requireRole } from './rbac';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const tableName = process.env.MAIN_TABLE || 'SecurityIncidentTable';

interface AuditLogEntry {
  pk: string;
  sk: string;
  eventType: string;
  userId: string;
  targetResourceType: string;
  targetResourceId?: string;
  operationContent: string;
  changeBeforeValue?: string;
  changeAfterValue?: string;
  ipAddress?: string;
  sessionId?: string;
  severity: string;
  status: string;
  createdAt: number;
  updatedAt: number;
}

function createAuditLog(
  userId: string,
  eventType: string,
  targetResourceType: string,
  operationContent: string,
  targetResourceId?: string,
  changeBeforeValue?: string,
  changeAfterValue?: string,
  ipAddress?: string,
  sessionId?: string
): AuditLogEntry {
  const now = Date.now();
  return {
    pk: 'AUDIT',
    sk: `${now}#${randomUUID()}`,
    eventType,
    userId,
    targetResourceType,
    targetResourceId,
    operationContent,
    changeBeforeValue,
    changeAfterValue,
    ipAddress,
    sessionId,
    severity: 'medium',
    status: 'unprocessed',
    createdAt: now,
    updatedAt: now,
  };
}

async function logAudit(auditEntry: AuditLogEntry): Promise<void> {
  try {
    await docClient.send(
      new PutCommand({
        TableName: tableName,
        Item: auditEntry,
      })
    );
  } catch (error) {
    console.error('Failed to write audit log:', error);
  }
}

function errorResponse(statusCode: number, message: string): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify({ error: message }),
  };
}

function successResponse(statusCode: number, data: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify(data),
  };
}

async function handleGetResources(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    requirePermission(context, 'auditLogView');

    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'attribute_exists(pk) AND pk <> :auditPk',
        ExpressionAttributeValues: {
          ':auditPk': 'AUDIT',
        },
      })
    );

    return successResponse(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    if (message.includes('Missing') || message.includes('Invalid')) {
      return errorResponse(400, message);
    }
    return errorResponse(500, message);
  }
}

async function handleBulkImport(
  event: APIGatewayProxyEvent,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    requireRole(context, 'admin', 'operator');

    const body = JSON.parse(event.body || '{}');
    const items: Record<string, unknown>[] = body.items || [];

    if (!Array.isArray(items) || items.length === 0) {
      return errorResponse(400, 'items must be a non-empty array');
    }

    const now = Date.now();
    const enrichedItems = items.map((item) => ({
      ...item,
      id: (item as Record<string, unknown>).id || randomUUID(),
      createdAt: now,
      updatedAt: now,
      pk: `${tableIndex}`,
      sk: (item as Record<string, unknown>).id || randomUUID(),
    }));

    const chunks: typeof enrichedItems[] = [];
    for (let i = 0; i < enrichedItems.length; i += 25) {
      chunks.push(enrichedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      const writeRequests = chunk.map((item) => ({
        PutRequest: {
          Item: item,
        },
      }));

      const params: BatchWriteItemCommandInput = {
        RequestItems: {
          [tableName]: writeRequests,
        },
      };

      try {
        await client.send(new BatchWriteItemCommand(params));
        imported += chunk.length;
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        errors.push(`Batch write failed: ${errorMsg}`);
      }
    }

    const auditEntry = createAuditLog(
      context.userId,
      'BULK_IMPORT',
      `TABLE_${tableIndex}`,
      `Bulk imported ${imported} items`,
      undefined,
      undefined,
      undefined,
      event.requestContext?.identity?.sourceIp,
      event.requestContext?.requestId
    );
    await logAudit(auditEntry);

    return successResponse(200, {
      imported,
      failed: items.length - imported,
      errors,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    if (message.includes('Missing') || message.includes('Invalid')) {
      return errorResponse(400, message);
    }
    return errorResponse(500, message);
  }
}

async function handleGetResourceById(
  event: APIGatewayProxyEvent,
  resourceId: string
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    requirePermission(context, 'auditLogView');

    const result = await docClient.send(
      new GetCommand({
        TableName: tableName,
        Key: {
          pk: resourceId,
          sk: resourceId,
        },
      })
    );

    if (!result.Item) {
      return errorResponse(404, 'Resource not found');
    }

    return successResponse(200, result.Item);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    if (message.includes('Missing') || message.includes('Invalid')) {
      return errorResponse(400, message);
    }
    return errorResponse(500, message);
  }
}

async function handleCreateResource(
  event: APIGatewayProxyEvent,
  resourceType: string
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);

    if (resourceType === 'vulnerability') {
      requirePermission(context, 'vulnerabilityManage');
    } else if (resourceType === 'incident') {
      requirePermission(context, 'incidentRespond');
    } else if (resourceType === 'asset') {
      requirePermission(context, 'assetManage');
    }

    const body = JSON.parse(event.body || '{}');
    const now = Date.now();
    const resourceId = randomUUID();

    const item = {
      ...body,
      pk: resourceType,
      sk: resourceId,
      id: resourceId,
      createdAt: now,
      updatedAt: now,
      createdBy: context.userId,
      updatedBy: context.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: tableName,
        Item: item,
      })
    );

    const auditEntry = createAuditLog(
      context.userId,
      'CREATE',
      resourceType,
      `Created new ${resourceType}`,
      resourceId,
      undefined,
      JSON.stringify(body),
      event.requestContext?.identity?.sourceIp,
      event.requestContext?.requestId
    );
    await logAudit(auditEntry);

    return successResponse(201, item);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    if (message.includes('Missing') || message.includes('Invalid')) {
      return errorResponse(400, message);
    }
    return errorResponse(500, message);
  }
}

async function handleUpdateResource(
  event: APIGatewayProxyEvent,
  resourceType: string,
  resourceId: string
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);

    if (resourceType === 'vulnerability') {
      requirePermission(context, 'vulnerabilityManage');
    } else if (resourceType === 'incident') {
      requirePermission(context, 'incidentRespond');
    } else if (resourceType === 'asset') {
      requirePermission(context, 'assetManage');
    }

    const body = JSON.parse(event.body || '{}');
    const now = Date.now();

    const getResult = await docClient.send(
      new GetCommand({
        TableName: tableName,
        Key: {
          pk: resourceType,
          sk: resourceId,
        },
      })
    );

    if (!getResult.Item) {
      return errorResponse(404, 'Resource not found');
    }

    const oldItem = JSON.stringify(getResult.Item);

    const updateItem = {
      ...getResult.Item,
      ...body,
      updatedAt: now,
      updatedBy: context.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: tableName,
        Item: updateItem,
      })
    );

    const auditEntry = createAuditLog(
      context.userId,
      'UPDATE',
      resourceType,
      `Updated ${resourceType}`,
      resourceId,
      oldItem,
      JSON.stringify(updateItem),
      event.requestContext?.identity?.sourceIp,
      event.requestContext?.requestId
    );
    await logAudit(auditEntry);

    return successResponse(200, updateItem);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    if (message.includes('Missing') || message.includes('Invalid')) {
      return errorResponse(400, message);
    }
    return errorResponse(500, message);
  }
}

async function handleDeleteResource(
  event: APIGatewayProxyEvent,
  resourceType: string,
  resourceId: string
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    requireRole(context, 'admin');

    const getResult = await docClient.send(
      new GetCommand({
        TableName: tableName,
        Key: {
          pk: resourceType,
          sk: resourceId,
        },
      })
    );

    if (!getResult.Item) {
      return errorResponse(404, 'Resource not found');
    }

    await docClient.send(
      new DeleteCommand({
        TableName: tableName,
        Key: {
          pk: resourceType,
          sk: resourceId,
        },
      })
    );

    const auditEntry = createAuditLog(
      context.userId,
      'DELETE',
      resourceType,
      `Deleted ${resourceType}`,
      resourceId,
      JSON.stringify(getResult.Item),
      undefined,
      event.requestContext?.identity?.sourceIp,
      event.requestContext?.requestId
    );
    await logAudit(auditEntry);

    return successResponse(204, null);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    if (message.includes('Missing') || message.includes('Invalid')) {
      return errorResponse(400, message);
    }
    return errorResponse(500, message);
  }
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const path = event.path || '';
  const method = event.httpMethod || 'GET';

  try {
    if (method === 'GET' && path === '/resources') {
      return await handleGetResources(event);
    }

    const bulkMatch = path.match(/^\/api\/(\w+)\/bulk$/);
    if (method === 'POST' && bulkMatch) {
      const tableIndex = bulkMatch[1];
      return await handleBulkImport(event, tableIndex);
    }

    const getByIdMatch = path.match(/^\/resources\/(\w+)$/);
    if (method === 'GET' && getByIdMatch) {
      const resourceId = getByIdMatch[1];
      return await handleGetResourceById(event, resourceId);
    }

    const createMatch = path.match(/^\/resources\/(\w+)$/);
    if (method === 'POST' && createMatch) {
      const resourceType = createMatch[1];
      return await handleCreateResource(event, resourceType);
    }

    const updateMatch = path.match(/^\/resources\/(\w+)\/(\w+)$/);
    if (method === 'PUT' && updateMatch) {
      const resourceType = updateMatch[1];
      const resourceId = updateMatch[2];
      return await handleUpdateResource(event, resourceType, resourceId);
    }

    const deleteMatch = path.match(/^\/resources\/(\w+)\/(\w+)$/);
    if (method === 'DELETE' && deleteMatch) {
      const resourceType = deleteMatch[1];
      const resourceId = deleteMatch[2];
      return await handleDeleteResource(event, resourceType, resourceId);
    }

    return errorResponse(404, 'Not found');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return errorResponse(500, message);
  }
}