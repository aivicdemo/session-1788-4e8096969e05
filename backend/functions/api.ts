import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  BatchWriteItemCommandInput,
} from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  ScanCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'crypto';
import {
  extractRBACContext,
  requirePermission,
  ForbiddenError,
  NotFoundError,
  ValidationError,
  RBACContext,
} from './rbac';

const client = new DynamoDBClient({ region: 'ap-northeast-1' });
const docClient = DynamoDBDocumentClient.from(client);
const tableName = process.env.MAIN_TABLE || 'SecurityIncidentTable';

interface AuditLogEntry {
  pk: string;
  sk: string;
  eventType: string;
  userId?: string;
  targetResourceType: string;
  targetResourceId?: string;
  operationContent: string;
  beforeValue?: string;
  afterValue?: string;
  ipAddress?: string;
  sessionId?: string;
  severity: string;
  status: string;
  createdAt: number;
  updatedAt: number;
}

interface Resource {
  id: string;
  [key: string]: unknown;
  createdAt: number;
  updatedAt: number;
}

const tableIndexMap: Record<string, string> = {
  '0': 'USER',
  '1': 'VULNERABILITY',
  '2': 'SCAN_RESULT',
  '3': 'AUDIT_LOG',
  '4': 'TICKET',
  '5': 'RESPONSE_HISTORY',
  '6': 'IMPACT_ANALYSIS',
  '7': 'REPORT',
  '8': 'ASSET',
  '9': 'PERMISSION',
  '10': 'VULNERABILITY_MASTER',
};

function getTablePrefix(tableIndex: string): string {
  const prefix = tableIndexMap[tableIndex];
  if (!prefix) {
    throw new ValidationError(`Invalid table index: ${tableIndex}`);
  }
  return prefix;
}

async function createAuditLog(
  context: RBACContext,
  eventType: string,
  targetResourceType: string,
  targetResourceId: string | undefined,
  operationContent: string,
  beforeValue?: string,
  afterValue?: string,
  ipAddress?: string
): Promise<void> {
  const auditEntry: AuditLogEntry = {
    pk: 'AUDIT',
    sk: `${Date.now()}#${randomUUID()}`,
    eventType,
    userId: context.userId,
    targetResourceType,
    targetResourceId,
    operationContent,
    beforeValue,
    afterValue,
    ipAddress: ipAddress || 'unknown',
    sessionId: randomUUID(),
    severity: 'INFO',
    status: 'COMPLETED',
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };

  await docClient.send(
    new PutCommand({
      TableName: tableName,
      Item: auditEntry,
    })
  );
}

function buildResponse(
  statusCode: number,
  body: Record<string, unknown> | string
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  };
}

async function handleGetResources(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(context, 'auditLogView');

    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'attribute_exists(id)',
        Limit: 100,
      })
    );

    const resources = (result.Items || []).filter(
      (item) => item.pk && item.pk !== 'AUDIT'
    );

    return buildResponse(200, {
      success: true,
      count: resources.length,
      resources,
    });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return buildResponse(403, { error: error.message });
    }
    console.error('Error in handleGetResources:', error);
    return buildResponse(500, { error: 'Internal server error' });
  }
}

async function handleBulkImport(
  event: APIGatewayProxyEvent,
  context: RBACContext,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(context, 'bulkImport');

    const body = JSON.parse(event.body || '{}');
    const items = body.items as Record<string, unknown>[];

    if (!Array.isArray(items) || items.length === 0) {
      return buildResponse(400, {
        error: 'Invalid request: items must be a non-empty array',
      });
    }

    const prefix = getTablePrefix(tableIndex);
    const now = Date.now();
    const enrichedItems: Record<string, unknown>[] = [];

    for (const item of items) {
      enrichedItems.push({
        ...item,
        pk: prefix,
        sk: `${item.id || randomUUID()}#${now}`,
        id: item.id || randomUUID(),
        createdAt: now,
        updatedAt: now,
        createdBy: context.userId,
        updatedBy: context.userId,
      });
    }

    const batchSize = 25;
    let imported = 0;
    let failed = 0;
    const errors: string[] = [];

    for (let i = 0; i < enrichedItems.length; i += batchSize) {
      const batch = enrichedItems.slice(i, i + batchSize);
      const writeRequests = batch.map((item) => ({
        PutRequest: {
          Item: item as Record<string, unknown>,
        },
      }));

      try {
        const params: BatchWriteItemCommandInput = {
          RequestItems: {
            [tableName]: writeRequests as never,
          },
        };

        await client.send(new BatchWriteItemCommand(params));
        imported += batch.length;
      } catch (batchError) {
        failed += batch.length;
        errors.push(
          `Batch ${Math.floor(i / batchSize) + 1} failed: ${String(batchError)}`
        );
      }
    }

    await createAuditLog(
      context,
      'BULK_IMPORT',
      prefix,
      undefined,
      `Bulk imported ${imported} items to ${prefix}`,
      undefined,
      JSON.stringify({ imported, failed }),
      event.requestContext?.identity?.sourceIp
    );

    return buildResponse(200, {
      success: true,
      imported,
      failed,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return buildResponse(403, { error: error.message });
    }
    if (error instanceof ValidationError) {
      return buildResponse(400, { error: error.message });
    }
    console.error('Error in handleBulkImport:', error);
    return buildResponse(500, { error: 'Internal server error' });
  }
}

async function handleGetResourceById(
  event: APIGatewayProxyEvent,
  context: RBACContext,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(context, 'auditLogView');

    const resourceId = event.pathParameters?.id;
    if (!resourceId) {
      return buildResponse(400, { error: 'Missing resource ID' });
    }

    const prefix = getTablePrefix(tableIndex);

    const result = await docClient.send(
      new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: 'pk = :pk AND begins_with(sk, :sk)',
        ExpressionAttributeValues: {
          ':pk': prefix,
          ':sk': `${resourceId}#`,
        },
        Limit: 1,
      })
    );

    if (!result.Items || result.Items.length === 0) {
      return buildResponse(404, { error: 'Resource not found' });
    }

    return buildResponse(200, {
      success: true,
      resource: result.Items[0],
    });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return buildResponse(403, { error: error.message });
    }
    if (error instanceof ValidationError) {
      return buildResponse(400, { error: error.message });
    }
    console.error('Error in handleGetResourceById:', error);
    return buildResponse(500, { error: 'Internal server error' });
  }
}

async function handleCreateResource(
  event: APIGatewayProxyEvent,
  context: RBACContext,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(context, 'vulnerabilityManage');

    const body = JSON.parse(event.body || '{}');
    const prefix = getTablePrefix(tableIndex);
    const now = Date.now();
    const resourceId = randomUUID();

    const resource: Resource = {
      ...body,
      pk: prefix,
      sk: `${resourceId}#${now}`,
      id: resourceId,
      createdAt: now,
      updatedAt: now,
      createdBy: context.userId,
      updatedBy: context.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: tableName,
        Item: resource,
      })
    );

    await createAuditLog(
      context,
      'CREATE',
      prefix,
      resourceId,
      `Created new ${prefix} resource`,
      undefined,
      JSON.stringify(resource),
      event.requestContext?.identity?.sourceIp
    );

    return buildResponse(201, {
      success: true,
      resource,
    });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return buildResponse(403, { error: error.message });
    }
    if (error instanceof ValidationError) {
      return buildResponse(400, { error: error.message });
    }
    console.error('Error in handleCreateResource:', error);
    return buildResponse(500, { error: 'Internal server error' });
  }
}

async function handleUpdateResource(
  event: APIGatewayProxyEvent,
  context: RBACContext,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(context, 'vulnerabilityManage');

    const resourceId = event.pathParameters?.id;
    if (!resourceId) {
      return buildResponse(400, { error: 'Missing resource ID' });
    }

    const body = JSON.parse(event.body || '{}');
    const prefix = getTablePrefix(tableIndex);
    const now = Date.now();

    const queryResult = await docClient.send(
      new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: 'pk = :pk AND begins_with(sk, :sk)',
        ExpressionAttributeValues: {
          ':pk': prefix,
          ':sk': `${resourceId}#`,
        },
        Limit: 1,
      })
    );

    if (!queryResult.Items || queryResult.Items.length === 0) {
      return buildResponse(404, { error: 'Resource not found' });
    }

    const oldItem = queryResult.Items[0];
    const sk = oldItem.sk as string;

    const updateExpressions: string[] = [];
    const expressionAttributeNames: Record<string, string> = {};
    const expressionAttributeValues: Record<string, unknown> = {};

    Object.entries(body).forEach(([key, value], index) => {
      if (key !== 'pk' && key !== 'sk' && key !== 'id') {
        const attrName = `#attr${index}`;
        const attrValue = `:val${index}`;
        updateExpressions.push(`${attrName} = ${attrValue}`);
        expressionAttributeNames[attrName] = key;
        expressionAttributeValues[attrValue] = value;
      }
    });

    updateExpressions.push('#updatedAt = :updatedAt');
    updateExpressions.push('#updatedBy = :updatedBy');
    expressionAttributeNames['#updatedAt'] = 'updatedAt';
    expressionAttributeNames['#updatedBy'] = 'updatedBy';
    expressionAttributeValues[':updatedAt'] = now;
    expressionAttributeValues[':updatedBy'] = context.userId;

    await docClient.send(
      new UpdateCommand({
        TableName: tableName,
        Key: {
          pk: prefix,
          sk,
        },
        UpdateExpression: `SET ${updateExpressions.join(', ')}`,
        ExpressionAttributeNames: expressionAttributeNames,
        ExpressionAttributeValues: expressionAttributeValues,
      })
    );

    await createAuditLog(
      context,
      'UPDATE',
      prefix,
      resourceId,
      `Updated ${prefix} resource`,
      JSON.stringify(oldItem),
      JSON.stringify(body),
      event.requestContext?.identity?.sourceIp
    );

    return buildResponse(200, {
      success: true,
      message: 'Resource updated successfully',
    });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return buildResponse(403, { error: error.message });
    }
    if (error instanceof ValidationError) {
      return buildResponse(400, { error: error.message });
    }
    console.error('Error in handleUpdateResource:', error);
    return buildResponse(500, { error: 'Internal server error' });
  }
}

async function handleDeleteResource(
  event: APIGatewayProxyEvent,
  context: RBACContext,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(context, 'vulnerabilityManage');

    const resourceId = event.pathParameters?.id;
    if (!resourceId) {
      return buildResponse(400, { error: 'Missing resource ID' });
    }

    const prefix = getTablePrefix(tableIndex);

    const queryResult = await docClient.send(
      new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: 'pk = :pk AND begins_with(sk, :sk)',
        ExpressionAttributeValues: {
          ':pk': prefix,
          ':sk': `${resourceId}#`,
        },
        Limit: 1,
      })
    );

    if (!queryResult.Items || queryResult.Items.length === 0) {
      return buildResponse(404, { error: 'Resource not found' });
    }

    const item = queryResult.Items[0];
    const sk = item.sk as string;

    await docClient.send(
      new DeleteCommand({
        TableName: tableName,
        Key: {
          pk: prefix,
          sk,
        },
      })
    );

    await createAuditLog(
      context,
      'DELETE',
      prefix,
      resourceId,
      `Deleted ${prefix} resource`,
      JSON.stringify(item),
      undefined,
      event.requestContext?.identity?.sourceIp
    );

    return buildResponse(200, {
      success: true,
      message: 'Resource deleted successfully',
    });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return buildResponse(403, { error: error.message });
    }
    if (error instanceof ValidationError) {
      return buildResponse(400, { error: error.message });
    }
    console.error('Error in handleDeleteResource:', error);
    return buildResponse(500, { error: 'Internal server error' });
  }
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    const path = event.path || '';
    const method = event.httpMethod || 'GET';

    if (path === '/resources' && method === 'GET') {
      return await handleGetResources(event, context);
    }

    const bulkMatch = path.match(/^\/api\/(\d+)\/bulk$/);
    if (bulkMatch && method === 'POST') {
      return await handleBulkImport(event, context, bulkMatch[1]);
    }

    const getByIdMatch = path.match(/^\/api\/(\d+)\/([a-f0-9-]+)$/);
    if (getByIdMatch && method === 'GET') {
      return await handleGetResourceById(event, context, getByIdMatch[1]);
    }

    const createMatch = path.match(/^\/api\/(\d+)$/);
    if (createMatch && method === 'POST') {
      return await handleCreateResource(event, context, createMatch[1]);
    }

    if (getByIdMatch && method === 'PUT') {
      return await handleUpdateResource(event, context, getByIdMatch[1]);
    }

    if (getByIdMatch && method === 'DELETE') {
      return await handleDeleteResource(event, context, getByIdMatch[1]);
    }

    return buildResponse(404, { error: 'Endpoint not found' });
  } catch (error) {
    if (error instanceof Error && error.message.includes('Missing authorization')) {
      return buildResponse(401, { error: 'Unauthorized' });
    }
    console.error('Unhandled error:', error);
    return buildResponse(500, { error: 'Internal server error' });
  }
}