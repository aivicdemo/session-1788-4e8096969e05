import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  BatchWriteItemCommandInput,
} from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  ScanCommand,
  QueryCommand,
  GetCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
} from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'crypto';
import { extractRBACContext, requirePermission, RBACContext } from './rbac';

const client = new DynamoDBClient({ region: process.env.AWS_REGION || 'ap-northeast-1' });
const docClient = DynamoDBDocumentClient.from(client);
const tableName = process.env.MAIN_TABLE || 'SecurityIncidentTable';

interface ApiResponse {
  statusCode: number;
  body: string;
}

function response(statusCode: number, data: unknown): ApiResponse {
  return {
    statusCode,
    body: JSON.stringify(data),
  };
}

function errorResponse(statusCode: number, message: string): ApiResponse {
  return response(statusCode, { error: message });
}

async function createAuditLog(
  context: RBACContext,
  eventType: string,
  resourceType: string,
  resourceId: string | undefined,
  operation: string,
  beforeValue?: string,
  afterValue?: string,
  ipAddress?: string
): Promise<void> {
  const auditLogId = randomUUID();
  const now = new Date().toISOString();

  const auditLog = {
    pk: 'AUDIT',
    sk: `${now}#${auditLogId}`,
    auditLogId,
    eventType,
    userId: context.userId,
    resourceType,
    resourceId,
    operation,
    beforeValue,
    afterValue,
    ipAddress: ipAddress || 'unknown',
    severity: 'info',
    status: 'completed',
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

async function handleGetResources(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<ApiResponse> {
  try {
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

    return response(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
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
): Promise<ApiResponse> {
  try {
    requirePermission(context, 'bulkImport');

    if (!event.body) {
      return errorResponse(400, 'Request body is required');
    }

    let payload: { items: Record<string, unknown>[] };
    try {
      payload = JSON.parse(event.body);
    } catch {
      return errorResponse(400, 'Invalid JSON in request body');
    }

    if (!Array.isArray(payload.items)) {
      return errorResponse(400, 'items must be an array');
    }

    const now = new Date().toISOString();
    const enrichedItems = payload.items.map((item) => ({
      ...item,
      pk: tableIndex.toUpperCase(),
      sk: randomUUID(),
      id: randomUUID(),
      createdAt: now,
      updatedAt: now,
      createdBy: context.userId,
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

      const batchParams: BatchWriteItemCommandInput = {
        RequestItems: {
          [tableName]: writeRequests,
        },
      };

      try {
        await client.send(new BatchWriteItemCommand(batchParams));
        imported += chunk.length;
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        errors.push(`Batch write failed: ${errorMsg}`);
      }
    }

    await createAuditLog(
      context,
      'BULK_IMPORT',
      tableIndex,
      undefined,
      `Bulk imported ${imported} items`,
      undefined,
      undefined,
      event.requestContext?.identity?.sourceIp
    );

    return response(200, {
      imported,
      failed: payload.items.length - imported,
      errors,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    return errorResponse(500, message);
  }
}

async function handleGetUsers(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<ApiResponse> {
  try {
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': 'USER',
        },
      })
    );

    return response(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

async function handleGetVulnerabilities(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<ApiResponse> {
  try {
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': 'VULNERABILITY',
        },
      })
    );

    return response(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

async function handleGetScanResults(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<ApiResponse> {
  try {
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': 'SCANRESULT',
        },
      })
    );

    return response(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

async function handleGetAuditLogs(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<ApiResponse> {
  try {
    requirePermission(context, 'auditLogView');

    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': 'AUDIT',
        },
      })
    );

    return response(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    return errorResponse(500, message);
  }
}

async function handleGetTickets(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<ApiResponse> {
  try {
    requirePermission(context, 'incidentRespond');

    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': 'TICKET',
        },
      })
    );

    return response(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    return errorResponse(500, message);
  }
}

async function handleGetReports(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<ApiResponse> {
  try {
    requirePermission(context, 'reportGenerate');

    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': 'REPORT',
        },
      })
    );

    return response(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    return errorResponse(500, message);
  }
}

async function handleGetImpactAnalysis(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<ApiResponse> {
  try {
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': 'IMPACT',
        },
      })
    );

    return response(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

async function handleGetPermissions(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<ApiResponse> {
  try {
    requirePermission(context, 'permissionDelete');

    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': 'PERMISSION',
        },
      })
    );

    return response(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Forbidden')) {
      return errorResponse(403, message);
    }
    return errorResponse(500, message);
  }
}

async function handleGetVulnerabilityMaster(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<ApiResponse> {
  try {
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': 'VULNMASTER',
        },
      })
    );

    return response(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

async function handleGetStatusHistory(
  event: APIGatewayProxyEvent,
  context: RBACContext
): Promise<ApiResponse> {
  try {
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': 'STATUSHISTORY',
        },
      })
    );

    return response(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return errorResponse(500, message);
  }
}

export async function handler(event: APIGatewayProxyEvent): Promise<ApiResponse> {
  try {
    const context = extractRBACContext(event);
    const path = event.path || '';
    const method = event.httpMethod || 'GET';

    if (method === 'GET' && path === '/resources') {
      return await handleGetResources(event, context);
    }

    if (method === 'GET' && path === '/users') {
      return await handleGetUsers(event, context);
    }

    if (method === 'GET' && path === '/vulnerabilities') {
      return await handleGetVulnerabilities(event, context);
    }

    if (method === 'GET' && path === '/scan-results') {
      return await handleGetScanResults(event, context);
    }

    if (method === 'GET' && path === '/audit-logs') {
      return await handleGetAuditLogs(event, context);
    }

    if (method === 'GET' && path === '/tickets') {
      return await handleGetTickets(event, context);
    }

    if (method === 'GET' && path === '/reports') {
      return await handleGetReports(event, context);
    }

    if (method === 'GET' && path === '/impact-analysis') {
      return await handleGetImpactAnalysis(event, context);
    }

    if (method === 'GET' && path === '/permissions') {
      return await handleGetPermissions(event, context);
    }

    if (method === 'GET' && path === '/vulnerability-master') {
      return await handleGetVulnerabilityMaster(event, context);
    }

    if (method === 'GET' && path === '/status-history') {
      return await handleGetStatusHistory(event, context);
    }

    const bulkImportMatch = path.match(/^\/api\/([a-z]+)\/bulk$/);
    if (method === 'POST' && bulkImportMatch) {
      const tableIndex = bulkImportMatch[1];
      return await handleBulkImport(event, context, tableIndex);
    }

    return errorResponse(404, 'Not found');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('Missing authorization') || message.includes('Invalid token')) {
      return errorResponse(401, message);
    }
    return errorResponse(500, message);
  }
}