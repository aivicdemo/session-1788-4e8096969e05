import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  DynamoDBClient,
  BatchWriteItemCommand,
} from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  ScanCommand,
  QueryCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
} from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'crypto';
import {
  extractRBACContext,
  requirePermission,
  ForbiddenError,
  NotFoundError,
  ValidationError,
} from './rbac';

const client = new DynamoDBClient({ region: 'ap-northeast-1' });
const docClient = DynamoDBDocumentClient.from(client);
const tableName = process.env.MAIN_TABLE || 'SecurityIncidentTable';

interface AuditLogEntry {
  pk: string;
  sk: string;
  auditLogId: string;
  eventType: string;
  userId?: string;
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

async function createAuditLog(
  eventType: string,
  userId: string,
  targetResourceType: string,
  targetResourceId: string | undefined,
  operationContent: string,
  severity: string,
  changeBeforeValue?: string,
  changeAfterValue?: string,
  ipAddress?: string,
  sessionId?: string
): Promise<void> {
  const now = Date.now();
  const auditLogId = randomUUID();
  const auditLog: AuditLogEntry = {
    pk: 'AUDIT',
    sk: `${now}#${auditLogId}`,
    auditLogId,
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
    status: '未処理',
    createdAt: now,
    updatedAt: now,
  };

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
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    requirePermission(context, 'assetManage');

    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': 'ASSET',
        },
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
    if (error instanceof Error) {
      return errorResponse(500, error.message);
    }
    return errorResponse(500, 'Internal server error');
  }
}

async function handleBulkImport(
  event: APIGatewayProxyEvent,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    requirePermission(context, 'bulkImport');

    if (!event.body) {
      return errorResponse(400, 'Request body is required');
    }

    const { items } = JSON.parse(event.body) as { items: Record<string, unknown>[] };

    if (!Array.isArray(items) || items.length === 0) {
      return errorResponse(400, 'items array is required and must not be empty');
    }

    const now = Date.now();
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

    const enrichedItems = items.map((item) => ({
      ...item,
      pk,
      sk: `${now}#${randomUUID()}`,
      id: randomUUID(),
      createdAt: now,
      updatedAt: now,
    }));

    const chunks = [];
    for (let i = 0; i < enrichedItems.length; i += 25) {
      chunks.push(enrichedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      const writeRequests = chunk.map((item) => ({
        PutRequest: {
          Item: Object.entries(item).reduce(
            (acc, [key, value]) => {
              if (value !== null && value !== undefined) {
                acc[key] = value;
              }
              return acc;
            },
            {} as Record<string, unknown>
          ),
        },
      }));

      try {
        await docClient.send(
          new BatchWriteItemCommand({
            RequestItems: {
              [tableName]: writeRequests,
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
      'BULK_IMPORT',
      context.userId,
      pk,
      undefined,
      `Bulk imported ${imported} items to ${pk}`,
      '中',
      undefined,
      undefined,
      event.requestContext?.identity?.sourceIp,
      event.requestContext?.requestId
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
    if (error instanceof Error) {
      return errorResponse(500, error.message);
    }
    return errorResponse(500, 'Internal server error');
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

    const bulkMatch = path.match(/^\/api\/(\d+)\/bulk$/);
    if (method === 'POST' && bulkMatch) {
      const tableIndex = bulkMatch[1];
      return await handleBulkImport(event, tableIndex);
    }

    return errorResponse(404, 'Not found');
  } catch (error) {
    console.error('Unhandled error:', error);
    return errorResponse(500, 'Internal server error');
  }
}