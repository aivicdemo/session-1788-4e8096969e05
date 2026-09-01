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

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE || 'SecurityIncidentTable';

interface AuditLogEntry {
  pk: string;
  sk: string;
  eventType: string;
  userId: string;
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

async function createAuditLog(
  context: RBACContext,
  eventType: string,
  targetResourceType: string,
  operationContent: string,
  targetResourceId?: string,
  beforeValue?: string,
  afterValue?: string,
  ipAddress?: string,
  severity: string = 'medium'
): Promise<void> {
  const auditLogId = randomUUID();
  const now = Date.now();

  const auditLog: AuditLogEntry = {
    pk: 'AUDIT',
    sk: `${now}#${auditLogId}`,
    eventType,
    userId: context.userId,
    targetResourceType,
    targetResourceId,
    operationContent,
    beforeValue,
    afterValue,
    ipAddress,
    sessionId: randomUUID(),
    severity,
    status: 'completed',
    createdAt: now,
    updatedAt: now,
  };

  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
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
  try {
    requirePermission(context, 'assetManage');

    const result = await docClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
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
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
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

    const body = JSON.parse(event.body || '{}');
    const items = body.items as Record<string, unknown>[];

    if (!Array.isArray(items)) {
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
      return errorResponse(400, `Invalid table index: ${tableIndex}`);
    }

    const now = Date.now();
    const enrichedItems = items.map((item) => ({
      ...item,
      pk,
      sk: item.sk || `${randomUUID()}`,
      id: item.id || randomUUID(),
      createdAt: item.createdAt || now,
      updatedAt: item.updatedAt || now,
    }));

    const chunks: Record<string, unknown>[][] = [];
    for (let i = 0; i < enrichedItems.length; i += 25) {
      chunks.push(enrichedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      const requests = chunk.map((item) => ({
        PutRequest: {
          Item: {
            pk: { S: String(item.pk) },
            sk: { S: String(item.sk) },
            ...Object.entries(item).reduce(
              (acc, [key, value]) => {
                if (key !== 'pk' && key !== 'sk') {
                  if (typeof value === 'string') {
                    acc[key] = { S: value };
                  } else if (typeof value === 'number') {
                    acc[key] = { N: String(value) };
                  } else if (typeof value === 'boolean') {
                    acc[key] = { BOOL: value };
                  } else if (value === null) {
                    acc[key] = { NULL: true };
                  } else {
                    acc[key] = { S: JSON.stringify(value) };
                  }
                }
                return acc;
              },
              {} as Record<string, unknown>
            ),
          },
        },
      }));

      try {
        await client.send(
          new BatchWriteItemCommand({
            RequestItems: {
              [TABLE_NAME]: requests,
            },
          })
        );
        imported += chunk.length;
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : 'Unknown error';
        errors.push(errMsg);
      }
    }

    await createAuditLog(
      context,
      'BULK_IMPORT',
      pk,
      `Bulk imported ${imported} items to ${pk}`,
      undefined,
      undefined,
      undefined,
      event.requestContext?.identity?.sourceIp,
      'high'
    );

    return successResponse(200, {
      imported,
      failed: items.length - imported,
      errors,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    return errorResponse(500, message);
  }
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

    return errorResponse(404, 'Not found');
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    if (message.includes('Missing or invalid Authorization')) {
      return errorResponse(401, message);
    }
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    return errorResponse(500, message);
  }
}