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
  checkPermissionOrThrow,
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

interface BulkImportRequest {
  items: Record<string, unknown>[];
}

interface BulkImportResponse {
  imported: number;
  failed: number;
  errors: string[];
}

function createAuditLog(
  eventType: string,
  userId: string,
  targetResourceType: string,
  operationContent: string,
  targetResourceId?: string,
  changeBeforeValue?: string,
  changeAfterValue?: string,
  ipAddress?: string,
  sessionId?: string,
  severity: string = 'medium',
  status: string = 'completed'
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
    severity,
    status,
    createdAt: now,
    updatedAt: now,
  };
}

async function writeAuditLog(auditLog: AuditLogEntry): Promise<void> {
  await docClient.send(
    new PutCommand({
      TableName: tableName,
      Item: auditLog,
    })
  );
}

function errorResponse(
  statusCode: number,
  message: string
): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify({ error: message }),
    headers: { 'Content-Type': 'application/json' },
  };
}

function successResponse(
  statusCode: number,
  data: unknown
): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify(data),
    headers: { 'Content-Type': 'application/json' },
  };
}

async function handleGetResources(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<APIGatewayProxyResult> {
  checkPermissionOrThrow(context, 'assetManage');

  const resourceId = event.pathParameters?.id;

  if (resourceId) {
    const result = await docClient.send(
      new GetCommand({
        TableName: tableName,
        Key: { pk: 'ASSET', sk: resourceId },
      })
    );

    if (!result.Item) {
      return errorResponse(404, 'Resource not found');
    }

    return successResponse(200, result.Item);
  }

  const result = await docClient.send(
    new QueryCommand({
      TableName: tableName,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: { ':pk': 'ASSET' },
    })
  );

  return successResponse(200, {
    items: result.Items || [],
    count: result.Count || 0,
  });
}

async function handleBulkImport(
  event: APIGatewayProxyEvent,
  context: RBACContext,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  checkPermissionOrThrow(context, 'bulkImport');

  let body: BulkImportRequest;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return errorResponse(400, 'Invalid JSON body');
  }

  if (!Array.isArray(body.items)) {
    return errorResponse(400, 'items must be an array');
  }

  const tableMap: Record<string, string> = {
    '0': 'USER',
    '1': 'VULNERABILITY',
    '2': 'SCAN_RESULT',
    '3': 'AUDIT',
    '4': 'TICKET',
    '5': 'RESPONSE_HISTORY',
    '6': 'IMPACT_ANALYSIS',
    '7': 'REPORT',
    '8': 'ASSET',
    '9': 'PERMISSION',
    '10': 'VULNERABILITY_MASTER',
  };

  const pk = tableMap[tableIndex];
  if (!pk) {
    return errorResponse(400, 'Invalid table index');
  }

  const now = Date.now();
  const items = body.items.map((item) => ({
    ...item,
    pk,
    sk: item.sk || randomUUID(),
    id: item.id || randomUUID(),
    createdAt: item.createdAt || now,
    updatedAt: item.updatedAt || now,
  }));

  const errors: string[] = [];
  let imported = 0;
  let failed = 0;

  for (let i = 0; i < items.length; i += 25) {
    const batch = items.slice(i, i + 25);
    const writeRequests = batch.map((item) => ({
      PutRequest: {
        Item: Object.entries(item).reduce(
          (acc, [key, value]) => {
            if (value === null || value === undefined) return acc;
            if (typeof value === 'string') {
              acc[key] = { S: value };
            } else if (typeof value === 'number') {
              acc[key] = { N: String(value) };
            } else if (typeof value === 'boolean') {
              acc[key] = { BOOL: value };
            } else if (Array.isArray(value)) {
              acc[key] = { SS: value.map(String) };
            } else {
              acc[key] = { S: JSON.stringify(value) };
            }
            return acc;
          },
          {} as Record<string, unknown>
        ),
      },
    }));

    const params: BatchWriteItemCommandInput = {
      RequestItems: {
        [tableName]: writeRequests,
      },
    };

    try {
      await client.send(new BatchWriteItemCommand(params));
      imported += batch.length;
    } catch (err) {
      failed += batch.length;
      errors.push(
        `Batch ${Math.floor(i / 25) + 1} failed: ${err instanceof Error ? err.message : 'Unknown error'}`
      );
    }
  }

  const auditLog = createAuditLog(
    'BULK_IMPORT',
    context.userId,
    pk,
    `Bulk imported ${imported} items to ${pk}`,
    undefined,
    undefined,
    undefined,
    event.requestContext?.identity?.sourceIp,
    event.requestContext?.requestId,
    'high',
    'completed'
  );

  await writeAuditLog(auditLog);

  return successResponse(200, {
    imported,
    failed,
    errors,
  } as BulkImportResponse);
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    const path = event.path || '';
    const method = event.httpMethod || 'GET';

    if (method === 'GET' && path === '/resources') {
      return await handleGetResources(event, context);
    }

    const bulkMatch = path.match(/^\/api\/(\d+)\/bulk$/);
    if (method === 'POST' && bulkMatch) {
      const tableIndex = bulkMatch[1];
      return await handleBulkImport(event, context, tableIndex);
    }

    return errorResponse(404, 'Endpoint not found');
  } catch (err) {
    if (err instanceof ForbiddenError) {
      return errorResponse(403, err.message);
    }
    if (err instanceof NotFoundError) {
      return errorResponse(404, err.message);
    }
    if (err instanceof ValidationError) {
      return errorResponse(400, err.message);
    }
    console.error('Unhandled error:', err);
    return errorResponse(
      500,
      err instanceof Error ? err.message : 'Internal server error'
    );
  }
}