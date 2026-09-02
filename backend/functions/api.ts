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

const client = new DynamoDBClient({ region: process.env.AWS_REGION || 'ap-northeast-1' });
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE || 'PublicFacilityDB';

interface AuditLog {
  pk: string;
  sk: string;
  operationId: string;
  userId: string;
  operationType: string;
  targetResourceType: string;
  targetResourceId: string;
  operationContent?: string;
  operationStatus: string;
  errorMessage?: string;
  executionStartTime: string;
  executionEndTime?: string;
  executionTimeSeconds?: number;
  ipAddress?: string;
  sessionId?: string;
  createdAt: string;
}

interface Resource {
  pk: string;
  sk: string;
  id: string;
  [key: string]: unknown;
  createdAt: string;
  updatedAt: string;
}

const TABLE_INDICES: Record<number, { name: string; pk: string; sk: string }> = {
  0: { name: 'users', pk: 'USER', sk: 'id' },
  1: { name: 'facilities', pk: 'FACILITY', sk: 'id' },
  2: { name: 'timeslots', pk: 'TIMESLOT', sk: 'id' },
  3: { name: 'reservations', pk: 'RESERVATION', sk: 'id' },
  4: { name: 'lotteries', pk: 'LOTTERY', sk: 'id' },
  5: { name: 'payments', pk: 'PAYMENT', sk: 'id' },
  6: { name: 'paymenthistory', pk: 'PAYMENTHISTORY', sk: 'id' },
  7: { name: 'cancellations', pk: 'CANCELLATION', sk: 'id' },
  8: { name: 'categories', pk: 'CATEGORY', sk: 'id' },
  9: { name: 'authlogs', pk: 'AUTHLOG', sk: 'id' },
};

async function createAuditLog(
  userId: string,
  operationType: string,
  targetResourceType: string,
  targetResourceId: string,
  operationStatus: string,
  operationContent?: string,
  errorMessage?: string,
  ipAddress?: string,
  sessionId?: string
): Promise<void> {
  const now = new Date().toISOString();
  const auditLog: AuditLog = {
    pk: 'AUDIT',
    sk: `${now}#${randomUUID()}`,
    operationId: randomUUID(),
    userId,
    operationType,
    targetResourceType,
    targetResourceId,
    operationStatus,
    executionStartTime: now,
    executionEndTime: now,
    executionTimeSeconds: 0,
    createdAt: now,
  };

  if (operationContent) auditLog.operationContent = operationContent;
  if (errorMessage) auditLog.errorMessage = errorMessage;
  if (ipAddress) auditLog.ipAddress = ipAddress;
  if (sessionId) auditLog.sessionId = sessionId;

  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: auditLog,
    })
  );
}

function getClientIp(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 'unknown';
}

function getSessionId(event: APIGatewayProxyEvent): string {
  return event.requestContext?.requestId || 'unknown';
}

async function handleGetResources(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'resources:read');

    const result = await docClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
        FilterExpression: 'attribute_exists(id)',
      })
    );

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        data: result.Items || [],
        count: result.Count || 0,
      }),
    };
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return {
        statusCode: 403,
        body: JSON.stringify({ success: false, error: error.message }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: 'Internal server error' }),
    };
  }
}

async function handleBulkImport(
  event: APIGatewayProxyEvent,
  tableIndex: number
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    const tableConfig = TABLE_INDICES[tableIndex];

    if (!tableConfig) {
      return {
        statusCode: 404,
        body: JSON.stringify({ success: false, error: 'Table not found' }),
      };
    }

    const permission = `${tableConfig.name}:bulk`;
    requirePermission(auth, permission);

    const body = JSON.parse(event.body || '{}');
    const items: Record<string, unknown>[] = body.items || [];

    if (!Array.isArray(items)) {
      return {
        statusCode: 400,
        body: JSON.stringify({ success: false, error: 'items must be an array' }),
      };
    }

    const now = new Date().toISOString();
    const processedItems: Resource[] = items.map((item) => ({
      pk: tableConfig.pk,
      sk: (item.id as string) || randomUUID(),
      id: (item.id as string) || randomUUID(),
      ...item,
      createdAt: now,
      updatedAt: now,
    }));

    const chunks: Resource[][] = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      const requestItems: Record<string, unknown>[] = chunk.map((item) => ({
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
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : 'Unknown error';
        errors.push(errorMsg);
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      tableConfig.name,
      `bulk_${randomUUID()}`,
      errors.length === 0 ? 'SUCCESS' : 'PARTIAL_SUCCESS',
      `Imported ${imported} items to ${tableConfig.name}`,
      errors.length > 0 ? errors.join('; ') : undefined,
      getClientIp(event),
      getSessionId(event)
    );

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        imported,
        failed: items.length - imported,
        errors,
      }),
    };
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return {
        statusCode: 403,
        body: JSON.stringify({ success: false, error: error.message }),
      };
    }
    if (error instanceof ValidationError) {
      return {
        statusCode: 400,
        body: JSON.stringify({ success: false, error: error.message }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: 'Internal server error' }),
    };
  }
}

async function handleGetResource(
  event: APIGatewayProxyEvent,
  tableIndex: number
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    const tableConfig = TABLE_INDICES[tableIndex];

    if (!tableConfig) {
      return {
        statusCode: 404,
        body: JSON.stringify({ success: false, error: 'Table not found' }),
      };
    }

    const permission = `${tableConfig.name}:read`;
    requirePermission(auth, permission);

    const id = event.pathParameters?.id;
    if (!id) {
      return {
        statusCode: 400,
        body: JSON.stringify({ success: false, error: 'ID is required' }),
      };
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: tableConfig.pk,
          sk: id,
        },
      })
    );

    if (!result.Item) {
      return {
        statusCode: 404,
        body: JSON.stringify({ success: false, error: 'Resource not found' }),
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true, data: result.Item }),
    };
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return {
        statusCode: 403,
        body: JSON.stringify({ success: false, error: error.message }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: 'Internal server error' }),
    };
  }
}

async function handleCreateResource(
  event: APIGatewayProxyEvent,
  tableIndex: number
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    const tableConfig = TABLE_INDICES[tableIndex];

    if (!tableConfig) {
      return {
        statusCode: 404,
        body: JSON.stringify({ success: false, error: 'Table not found' }),
      };
    }

    const permission = `${tableConfig.name}:create`;
    requirePermission(auth, permission);

    const body = JSON.parse(event.body || '{}');
    const now = new Date().toISOString();
    const id = body.id || randomUUID();

    const item: Resource = {
      pk: tableConfig.pk,
      sk: id,
      id,
      ...body,
      createdAt: now,
      updatedAt: now,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(
      auth.userId,
      'CREATE',
      tableConfig.name,
      id,
      'SUCCESS',
      `Created ${tableConfig.name} with ID ${id}`,
      undefined,
      getClientIp(event),
      getSessionId(event)
    );

    return {
      statusCode: 201,
      body: JSON.stringify({ success: true, data: item }),
    };
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return {
        statusCode: 403,
        body: JSON.stringify({ success: false, error: error.message }),
      };
    }
    if (error instanceof ValidationError) {
      return {
        statusCode: 400,
        body: JSON.stringify({ success: false, error: error.message }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: 'Internal server error' }),
    };
  }
}

async function handleUpdateResource(
  event: APIGatewayProxyEvent,
  tableIndex: number
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    const tableConfig = TABLE_INDICES[tableIndex];

    if (!tableConfig) {
      return {
        statusCode: 404,
        body: JSON.stringify({ success: false, error: 'Table not found' }),
      };
    }

    const permission = `${tableConfig.name}:update`;
    requirePermission(auth, permission);

    const id = event.pathParameters?.id;
    if (!id) {
      return {
        statusCode: 400,
        body: JSON.stringify({ success: false, error: 'ID is required' }),
      };
    }

    const body = JSON.parse(event.body || '{}');
    const now = new Date().toISOString();

    const updateExpression = Object.keys(body)
      .filter((key) => key !== 'pk' && key !== 'sk' && key !== 'id')
      .map((key) => `${key} = :${key}`)
      .join(', ');

    const expressionAttributeValues: Record<string, unknown> = {};
    Object.entries(body).forEach(([key, value]) => {
      if (key !== 'pk' && key !== 'sk' && key !== 'id') {
        expressionAttributeValues[`:${key}`] = value;
      }
    });
    expressionAttributeValues[':updatedAt'] = now;

    const finalUpdateExpression = updateExpression
      ? `${updateExpression}, updatedAt = :updatedAt`
      : 'updatedAt = :updatedAt';

    const result = await docClient.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: tableConfig.pk,
          sk: id,
        },
        UpdateExpression: finalUpdateExpression,
        ExpressionAttributeValues: expressionAttributeValues,
        ReturnValues: 'ALL_NEW',
      })
    );

    await createAuditLog(
      auth.userId,
      'UPDATE',
      tableConfig.name,
      id,
      'SUCCESS',
      `Updated ${tableConfig.name} with ID ${id}`,
      undefined,
      getClientIp(event),
      getSessionId(event)
    );

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true, data: result.Attributes }),
    };
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return {
        statusCode: 403,
        body: JSON.stringify({ success: false, error: error.message }),
      };
    }
    if (error instanceof ValidationError) {
      return {
        statusCode: 400,
        body: JSON.stringify({ success: false, error: error.message }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: 'Internal server error' }),
    };
  }
}

async function handleDeleteResource(
  event: APIGatewayProxyEvent,
  tableIndex: number
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    const tableConfig = TABLE_INDICES[tableIndex];

    if (!tableConfig) {
      return {
        statusCode: 404,
        body: JSON.stringify({ success: false, error: 'Table not found' }),
      };
    }

    const permission = `${tableConfig.name}:delete`;
    requirePermission(auth, permission);

    const id = event.pathParameters?.id;
    if (!id) {
      return {
        statusCode: 400,
        body: JSON.stringify({ success: false, error: 'ID is required' }),
      };
    }

    await docClient.send(
      new DeleteCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: tableConfig.pk,
          sk: id,
        },
      })
    );

    await createAuditLog(
      auth.userId,
      'DELETE',
      tableConfig.name,
      id,
      'SUCCESS',
      `Deleted ${tableConfig.name} with ID ${id}`,
      undefined,
      getClientIp(event),
      getSessionId(event)
    );

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true, message: 'Resource deleted' }),
    };
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return {
        statusCode: 403,
        body: JSON.stringify({ success: false, error: error.message }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: 'Internal server error' }),
    };
  }
}

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const path = event.path || '';
  const method = event.httpMethod || 'GET';

  try {
    if (path === '/resources' && method === 'GET') {
      return await handleGetResources(event);
    }

    const bulkMatch = path.match(/^\/api\/(\d+)\/bulk$/);
    if (bulkMatch && method === 'POST') {
      const tableIndex = parseInt(bulkMatch[1], 10);
      return await handleBulkImport(event, tableIndex);
    }

    const getMatch = path.match(/^\/api\/(\d+)\/(\w+)$/);
    if (getMatch && method === 'GET') {
      const tableIndex = parseInt(getMatch[1], 10);
      return await handleGetResource(event, tableIndex);
    }

    const createMatch = path.match(/^\/api\/(\d+)$/);
    if (createMatch && method === 'POST') {
      const tableIndex = parseInt(createMatch[1], 10);
      return await handleCreateResource(event, tableIndex);
    }

    const updateMatch = path.match(/^\/api\/(\d+)\/(\w+)$/);
    if (updateMatch && method === 'PUT') {
      const tableIndex = parseInt(updateMatch[1], 10);
      return await handleUpdateResource(event, tableIndex);
    }

    const deleteMatch = path.match(/^\/api\/(\d+)\/(\w+)$/);
    if (deleteMatch && method === 'DELETE') {
      const tableIndex = parseInt(deleteMatch[1], 10);
      return await handleDeleteResource(event, tableIndex);
    }

    return {
      statusCode: 404,
      body: JSON.stringify({ success: false, error: 'Endpoint not found' }),
    };
  } catch (error) {
    console.error('Unhandled error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: 'Internal server error' }),
    };
  }
};