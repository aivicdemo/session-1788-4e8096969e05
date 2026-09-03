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
import { extractRBACContext, requirePermission, RBACContext } from './rbac';

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

function createAuditLog(
  eventType: string,
  userId: string,
  targetResourceType: string,
  operationContent: string,
  severity: string = 'medium',
  targetResourceId?: string,
  changeBeforeValue?: string,
  changeAfterValue?: string
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
    severity,
    status: 'unprocessed',
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
  };
}

function successResponse(
  statusCode: number,
  data: unknown
): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify(data),
  };
}

async function handleGetResources(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(context, 'assetManage');

    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'begins_with(pk, :pk)',
        ExpressionAttributeValues: {
          ':pk': 'ASSET',
        },
      })
    );

    return successResponse(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

async function handleBulkImport(
  event: APIGatewayProxyEvent,
  context: RBACContext,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    requirePermission(context, 'bulkImport');

    if (!event.body) {
      return errorResponse(400, 'Request body is required');
    }

    const { items } = JSON.parse(event.body) as { items: Record<string, unknown>[] };

    if (!Array.isArray(items) || items.length === 0) {
      return errorResponse(400, 'items array is required and must not be empty');
    }

    const now = Date.now();
    const tablePrefix = getTablePrefix(tableIndex);
    const errors: string[] = [];
    let imported = 0;
    let failed = 0;

    const enrichedItems = items.map((item) => ({
      ...item,
      pk: `${tablePrefix}`,
      sk: `${item.id || randomUUID()}#${now}`,
      id: item.id || randomUUID(),
      createdAt: now,
      updatedAt: now,
      createdBy: context.userId,
      updatedBy: context.userId,
    }));

    const chunks = [];
    for (let i = 0; i < enrichedItems.length; i += 25) {
      chunks.push(enrichedItems.slice(i, i + 25));
    }

    for (const chunk of chunks) {
      const requests = chunk.map((item) => ({
        PutRequest: {
          Item: item,
        },
      }));

      try {
        await client.send(
          new BatchWriteItemCommand({
            RequestItems: {
              [tableName]: requests,
            },
          })
        );
        imported += chunk.length;
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : 'Batch write failed';
        errors.push(errorMsg);
        failed += chunk.length;
      }
    }

    const auditLog = createAuditLog(
      'BULK_IMPORT',
      context.userId,
      tablePrefix,
      `Bulk imported ${imported} items to ${tablePrefix}`,
      'high'
    );
    await writeAuditLog(auditLog);

    return successResponse(200, {
      imported,
      failed,
      errors,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

function getTablePrefix(tableIndex: string): string {
  const prefixes: Record<string, string> = {
    '1': 'USER',
    '2': 'VULNERABILITY',
    '3': 'SCAN_RESULT',
    '4': 'AUDIT',
    '5': 'TICKET',
    '6': 'RESPONSE_HISTORY',
    '7': 'IMPACT_ANALYSIS',
    '8': 'REPORT',
    '9': 'ASSET',
    '10': 'PERMISSION',
    '11': 'VULNERABILITY_MASTER',
  };
  return prefixes[tableIndex] || 'UNKNOWN';
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

    const bulkImportMatch = path.match(/^\/api\/(\d+)\/bulk$/);
    if (bulkImportMatch && method === 'POST') {
      const tableIndex = bulkImportMatch[1];
      return await handleBulkImport(event, context, tableIndex);
    }

    return errorResponse(404, 'Endpoint not found');
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    if (message.includes('Missing authorization') || message.includes('Invalid token')) {
      return errorResponse(401, message);
    }
    return errorResponse(500, message);
  }
}