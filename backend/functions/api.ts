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
const TABLE_NAME = process.env.MAIN_TABLE || 'public-facility-service';

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
}

interface User {
  id: string;
  email: string;
  passwordHash: string;
  name: string;
  phone: string;
  address?: string;
  status: string;
  createdAt: number;
  updatedAt: number;
}

interface Facility {
  id: string;
  name: string;
  description?: string;
  address: string;
  phone?: string;
  operatingStartTime: string;
  operatingEndTime: string;
  capacity: number;
  usageFee: number;
  reservableFlag: boolean;
  createdAt: number;
  updatedAt: number;
}

interface TimeSlot {
  id: string;
  facilityId: string;
  dayOfWeek: string;
  startTime: string;
  endTime: string;
  reservationUnitMinutes: number;
  maxReservationMinutes?: number;
  availableFlag: boolean;
  applicableStartDate?: number;
  applicableEndDate?: number;
  createdAt: number;
  updatedAt: number;
  createdBy?: string;
}

interface Reservation {
  id: string;
  userId: string;
  facilityId: string;
  timeSlotId: string;
  reservationDate: number;
  status: string;
  paymentStatus: string;
  amount: number;
  numberOfPeople?: number;
  notes?: string;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}

interface Lottery {
  id: string;
  userId: string;
  facilityId: string;
  timeSlotId: string;
  applicationDate: number;
  resultStatus: string;
  drawDate?: number;
  reservationId?: string;
  createdAt: number;
  updatedAt: number;
}

interface Payment {
  id: string;
  reservationId: string;
  userId: string;
  amount: number;
  method: string;
  status: string;
  paymentDate?: number;
  transactionId?: string;
  notes?: string;
  createdAt: number;
  updatedAt: number;
  createdBy?: string;
}

interface PaymentHistory {
  id: string;
  paymentId: string;
  reservationId: string;
  userId: string;
  amount: number;
  status: string;
  method: string;
  paymentDate: number;
  transactionId?: string;
  notes?: string;
  createdAt: number;
  updatedAt: number;
}

interface Cancellation {
  id: string;
  reservationId: string;
  userId: string;
  reason: string;
  reasonDetail?: string;
  cancellationFee: number;
  refundAmount: number;
  refundStatus: string;
  cancellationDate: number;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}

interface Category {
  id: string;
  name: string;
  description?: string;
  displayOrder?: number;
  activeFlag: boolean;
  createdAt: number;
  updatedAt: number;
  createdBy?: string;
}

interface AuthLog {
  id: string;
  userId: string;
  authType: string;
  authMethod: string;
  result: string;
  failureReason?: string;
  ipAddress: string;
  userAgent?: string;
  sessionId?: string;
  authDate: number;
  createdAt: number;
}

const TABLE_CONFIGS: Record<string, { pk: string; sk?: string }> = {
  '0': { pk: 'RESOURCE', sk: 'id' },
  '1': { pk: 'USER', sk: 'id' },
  '2': { pk: 'FACILITY', sk: 'id' },
  '3': { pk: 'TIMESLOT', sk: 'id' },
  '4': { pk: 'RESERVATION', sk: 'id' },
  '5': { pk: 'LOTTERY', sk: 'id' },
  '6': { pk: 'PAYMENT', sk: 'id' },
  '7': { pk: 'PAYMENTHISTORY', sk: 'id' },
  '8': { pk: 'CANCELLATION', sk: 'id' },
  '9': { pk: 'CATEGORY', sk: 'id' },
  '10': { pk: 'AUTHLOG', sk: 'id' },
};

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

function errorResponse(
  statusCode: number,
  message: string
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ error: message }),
  };
}

function successResponse(
  statusCode: number,
  data: unknown
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  };
}

async function handleGetResources(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'resources:read');

    const result = await docClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: { ':pk': 'RESOURCE' },
      })
    );

    return successResponse(200, { resources: result.Items || [] });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error fetching resources:', error);
    return errorResponse(500, 'Internal server error');
  }
}

async function handleBulkImport(
  event: APIGatewayProxyEvent,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    const tableConfig = TABLE_CONFIGS[tableIndex];

    if (!tableConfig) {
      return errorResponse(400, 'Invalid table index');
    }

    requirePermission(auth, `${tableConfig.pk.toLowerCase()}:bulk`);

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'Items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      ...item,
      pk: tableConfig.pk,
      sk: item.id || randomUUID(),
      id: item.id || randomUUID(),
      createdAt: item.createdAt || now,
      updatedAt: item.updatedAt || now,
    }));

    const errors: string[] = [];
    let imported = 0;
    let failed = 0;

    for (let i = 0; i < processedItems.length; i += 25) {
      const batch = processedItems.slice(i, i + 25);
      const requestItems: Record<string, unknown>[] = [];

      for (const item of batch) {
        requestItems.push({
          PutRequest: {
            Item: item,
          },
        });
      }

      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: requestItems,
            },
          })
        );
        imported += batch.length;
      } catch (batchError) {
        failed += batch.length;
        errors.push(
          `Batch ${Math.floor(i / 25)} failed: ${(batchError as Error).message}`
        );
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      tableConfig.pk,
      'bulk',
      {
        imported,
        failed,
        totalItems: processedItems.length,
      }
    );

    return successResponse(200, {
      imported,
      failed,
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

async function handleGetById(
  event: APIGatewayProxyEvent,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    const tableConfig = TABLE_CONFIGS[tableIndex];

    if (!tableConfig) {
      return errorResponse(400, 'Invalid table index');
    }

    const resourceType = tableConfig.pk.toLowerCase();
    requirePermission(auth, `${resourceType}:read`);

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'ID parameter is required');
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

async function handleCreate(
  event: APIGatewayProxyEvent,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    const tableConfig = TABLE_CONFIGS[tableIndex];

    if (!tableConfig) {
      return errorResponse(400, 'Invalid table index');
    }

    const resourceType = tableConfig.pk.toLowerCase();
    requirePermission(auth, `${resourceType}:create`);

    const body = JSON.parse(event.body || '{}');
    const now = Date.now();
    const id = randomUUID();

    const item = {
      ...body,
      pk: tableConfig.pk,
      sk: id,
      id,
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(auth.userId, 'CREATE', tableConfig.pk, id, body);

    return successResponse(201, item);
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

async function handleUpdate(
  event: APIGatewayProxyEvent,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    const tableConfig = TABLE_CONFIGS[tableIndex];

    if (!tableConfig) {
      return errorResponse(400, 'Invalid table index');
    }

    const resourceType = tableConfig.pk.toLowerCase();
    requirePermission(auth, `${resourceType}:update`);

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'ID parameter is required');
    }

    const body = JSON.parse(event.body || '{}');
    const now = Date.now();

    const updateExpression = Object.keys(body)
      .map((key, index) => `${key} = :val${index}`)
      .join(', ');

    const expressionAttributeValues: Record<string, unknown> = {};
    Object.entries(body).forEach(([key, value], index) => {
      expressionAttributeValues[`:val${index}`] = value;
    });
    expressionAttributeValues[':updatedAt'] = now;
    expressionAttributeValues[':updatedBy'] = auth.userId;

    const result = await docClient.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: tableConfig.pk,
          sk: id,
        },
        UpdateExpression: `SET ${updateExpression}, updatedAt = :updatedAt, updatedBy = :updatedBy`,
        ExpressionAttributeValues: expressionAttributeValues,
        ReturnValues: 'ALL_NEW',
      })
    );

    await createAuditLog(auth.userId, 'UPDATE', tableConfig.pk, id, body);

    return successResponse(200, result.Attributes);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error updating resource:', error);
    return errorResponse(500, 'Internal server error');
  }
}

async function handleDelete(
  event: APIGatewayProxyEvent,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    const tableConfig = TABLE_CONFIGS[tableIndex];

    if (!tableConfig) {
      return errorResponse(400, 'Invalid table index');
    }

    const resourceType = tableConfig.pk.toLowerCase();
    requirePermission(auth, `${resourceType}:delete`);

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'ID parameter is required');
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

    await createAuditLog(auth.userId, 'DELETE', tableConfig.pk, id, {});

    return successResponse(204, null);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error deleting resource:', error);
    return errorResponse(500, 'Internal server error');
  }
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const path = event.path || '';
  const method = event.httpMethod || 'GET';

  try {
    if (path === '/resources' && method === 'GET') {
      return await handleGetResources(event);
    }

    const bulkMatch = path.match(/^\/api\/(\d+)\/bulk$/);
    if (bulkMatch && method === 'POST') {
      return await handleBulkImport(event, bulkMatch[1]);
    }

    const getByIdMatch = path.match(/^\/api\/(\d+)\/([a-f0-9-]+)$/);
    if (getByIdMatch && method === 'GET') {
      return await handleGetById(event, getByIdMatch[1]);
    }

    const createMatch = path.match(/^\/api\/(\d+)$/);
    if (createMatch && method === 'POST') {
      return await handleCreate(event, createMatch[1]);
    }

    const updateMatch = path.match(/^\/api\/(\d+)\/([a-f0-9-]+)$/);
    if (updateMatch && method === 'PUT') {
      return await handleUpdate(event, updateMatch[1]);
    }

    const deleteMatch = path.match(/^\/api\/(\d+)\/([a-f0-9-]+)$/);
    if (deleteMatch && method === 'DELETE') {
      return await handleDelete(event, deleteMatch[1]);
    }

    return errorResponse(404, 'Endpoint not found');
  } catch (error) {
    console.error('Unhandled error:', error);
    return errorResponse(500, 'Internal server error');
  }
}