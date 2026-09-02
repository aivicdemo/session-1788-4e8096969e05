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
  resource: string;
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
  status: 'active' | 'inactive' | 'suspended';
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
  bookingAvailable: boolean;
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
  available: boolean;
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
  status: 'pending' | 'confirmed' | 'cancelled' | 'completed';
  paymentStatus: 'unpaid' | 'paid' | 'refunded';
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
  appliedAt: number;
  resultStatus: 'pending' | 'won' | 'lost';
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
  status: 'unpaid' | 'paid' | 'cancelled' | 'refunded';
  paidAt?: number;
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
  status: 'unpaid' | 'paid' | 'cancelled' | 'refunded';
  method: string;
  paidAt: number;
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
  reasonDetails?: string;
  cancellationFee: number;
  refundAmount: number;
  refundStatus: 'pending' | 'processing' | 'completed';
  cancelledAt: number;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}

interface Category {
  id: string;
  name: string;
  description?: string;
  displayOrder?: number;
  active: boolean;
  createdAt: number;
  updatedAt: number;
  createdBy?: string;
}

interface AuthLog {
  id: string;
  userId: string;
  authType: string;
  authMethod: string;
  result: 'success' | 'failure' | 'blocked';
  failureReason?: string;
  ipAddress: string;
  userAgent?: string;
  sessionId?: string;
  authAt: number;
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
  resource: string,
  resourceId: string,
  details: Record<string, unknown>
): Promise<void> {
  const auditLog: AuditLog = {
    pk: 'AUDIT',
    sk: `${Date.now()}#${randomUUID()}`,
    userId,
    action,
    resource,
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

function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validatePhone(phone: string): boolean {
  return phone.length >= 10 && phone.length <= 20;
}

function validateTimeFormat(time: string): boolean {
  const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
  return timeRegex.test(time);
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

// GET /resources
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

// POST /api/0/bulk - Resources bulk import
async function handleResourcesBulk(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'resources:bulk');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      pk: 'RESOURCE',
      sk: item.id || randomUUID(),
      ...item,
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    }));

    const chunks = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: chunk.map((item) => ({
                PutRequest: { Item: item },
              })),
            },
          })
        );
        imported += chunk.length;
      } catch (error) {
        errors.push(`Batch write failed: ${String(error)}`);
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      'RESOURCE',
      'bulk',
      { imported, failed: items.length - imported }
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
    console.error('Error in resources bulk import:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/1/bulk - Users bulk import
async function handleUsersBulk(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'users:bulk');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => {
      if (!item.email || !validateEmail(String(item.email))) {
        throw new ValidationError('Invalid email format');
      }
      if (!item.phone || !validatePhone(String(item.phone))) {
        throw new ValidationError('Invalid phone format');
      }
      return {
        pk: 'USER',
        sk: item.id || randomUUID(),
        ...item,
        createdAt: now,
        updatedAt: now,
      };
    });

    const chunks = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: chunk.map((item) => ({
                PutRequest: { Item: item },
              })),
            },
          })
        );
        imported += chunk.length;
      } catch (error) {
        errors.push(`Batch write failed: ${String(error)}`);
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      'USER',
      'bulk',
      { imported, failed: items.length - imported }
    );

    return successResponse(200, {
      imported,
      failed: items.length - imported,
      errors,
    });
  } catch (error) {
    if (error instanceof ValidationError) {
      return errorResponse(400, error.message);
    }
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error in users bulk import:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/2/bulk - Facilities bulk import
async function handleFacilitiesBulk(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'facilities:bulk');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => {
      if (!validateTimeFormat(String(item.operatingStartTime))) {
        throw new ValidationError('Invalid operatingStartTime format');
      }
      if (!validateTimeFormat(String(item.operatingEndTime))) {
        throw new ValidationError('Invalid operatingEndTime format');
      }
      return {
        pk: 'FACILITY',
        sk: item.id || randomUUID(),
        ...item,
        createdAt: now,
        updatedAt: now,
      };
    });

    const chunks = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: chunk.map((item) => ({
                PutRequest: { Item: item },
              })),
            },
          })
        );
        imported += chunk.length;
      } catch (error) {
        errors.push(`Batch write failed: ${String(error)}`);
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      'FACILITY',
      'bulk',
      { imported, failed: items.length - imported }
    );

    return successResponse(200, {
      imported,
      failed: items.length - imported,
      errors,
    });
  } catch (error) {
    if (error instanceof ValidationError) {
      return errorResponse(400, error.message);
    }
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error in facilities bulk import:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/3/bulk - TimeSlots bulk import
async function handleTimeSlotsBulk(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'timeslots:bulk');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => {
      if (!validateTimeFormat(String(item.startTime))) {
        throw new ValidationError('Invalid startTime format');
      }
      if (!validateTimeFormat(String(item.endTime))) {
        throw new ValidationError('Invalid endTime format');
      }
      return {
        pk: 'TIMESLOT',
        sk: item.id || randomUUID(),
        ...item,
        createdAt: now,
        updatedAt: now,
        createdBy: auth.userId,
      };
    });

    const chunks = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: chunk.map((item) => ({
                PutRequest: { Item: item },
              })),
            },
          })
        );
        imported += chunk.length;
      } catch (error) {
        errors.push(`Batch write failed: ${String(error)}`);
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      'TIMESLOT',
      'bulk',
      { imported, failed: items.length - imported }
    );

    return successResponse(200, {
      imported,
      failed: items.length - imported,
      errors,
    });
  } catch (error) {
    if (error instanceof ValidationError) {
      return errorResponse(400, error.message);
    }
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error in timeslots bulk import:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/4/bulk - Reservations bulk import
async function handleReservationsBulk(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'reservations:bulk');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      pk: 'RESERVATION',
      sk: item.id || randomUUID(),
      ...item,
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    }));

    const chunks = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: chunk.map((item) => ({
                PutRequest: { Item: item },
              })),
            },
          })
        );
        imported += chunk.length;
      } catch (error) {
        errors.push(`Batch write failed: ${String(error)}`);
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      'RESERVATION',
      'bulk',
      { imported, failed: items.length - imported }
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
    console.error('Error in reservations bulk import:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/5/bulk - Lotteries bulk import
async function handleLotteriesBulk(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'lotteries:bulk');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      pk: 'LOTTERY',
      sk: item.id || randomUUID(),
      ...item,
      createdAt: now,
      updatedAt: now,
    }));

    const chunks = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: chunk.map((item) => ({
                PutRequest: { Item: item },
              })),
            },
          })
        );
        imported += chunk.length;
      } catch (error) {
        errors.push(`Batch write failed: ${String(error)}`);
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      'LOTTERY',
      'bulk',
      { imported, failed: items.length - imported }
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
    console.error('Error in lotteries bulk import:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/6/bulk - Payments bulk import
async function handlePaymentsBulk(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'payments:bulk');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      pk: 'PAYMENT',
      sk: item.id || randomUUID(),
      ...item,
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    }));

    const chunks = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: chunk.map((item) => ({
                PutRequest: { Item: item },
              })),
            },
          })
        );
        imported += chunk.length;
      } catch (error) {
        errors.push(`Batch write failed: ${String(error)}`);
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      'PAYMENT',
      'bulk',
      { imported, failed: items.length - imported }
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
    console.error('Error in payments bulk import:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/7/bulk - PaymentHistory bulk import
async function handlePaymentHistoryBulk(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'paymenthistory:bulk');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      pk: 'PAYMENTHISTORY',
      sk: item.id || randomUUID(),
      ...item,
      createdAt: now,
      updatedAt: now,
    }));

    const chunks = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: chunk.map((item) => ({
                PutRequest: { Item: item },
              })),
            },
          })
        );
        imported += chunk.length;
      } catch (error) {
        errors.push(`Batch write failed: ${String(error)}`);
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      'PAYMENTHISTORY',
      'bulk',
      { imported, failed: items.length - imported }
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
    console.error('Error in payment history bulk import:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/8/bulk - Cancellations bulk import
async function handleCancellationsBulk(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'cancellations:bulk');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      pk: 'CANCELLATION',
      sk: item.id || randomUUID(),
      ...item,
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    }));

    const chunks = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: chunk.map((item) => ({
                PutRequest: { Item: item },
              })),
            },
          })
        );
        imported += chunk.length;
      } catch (error) {
        errors.push(`Batch write failed: ${String(error)}`);
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      'CANCELLATION',
      'bulk',
      { imported, failed: items.length - imported }
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
    console.error('Error in cancellations bulk import:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/9/bulk - Categories bulk import
async function handleCategoriesBulk(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'categories:bulk');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      pk: 'CATEGORY',
      sk: item.id || randomUUID(),
      ...item,
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    }));

    const chunks = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: chunk.map((item) => ({
                PutRequest: { Item: item },
              })),
            },
          })
        );
        imported += chunk.length;
      } catch (error) {
        errors.push(`Batch write failed: ${String(error)}`);
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      'CATEGORY',
      'bulk',
      { imported, failed: items.length - imported }
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
    console.error('Error in categories bulk import:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/10/bulk - AuthLogs bulk import
async function handleAuthLogsBulk(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const auth = extractAuthContext(event);
    requirePermission(auth, 'authlogs:bulk');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      return errorResponse(400, 'items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      pk: 'AUTHLOG',
      sk: item.id || randomUUID(),
      ...item,
      createdAt: now,
    }));

    const chunks = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: chunk.map((item) => ({
                PutRequest: { Item: item },
              })),
            },
          })
        );
        imported += chunk.length;
      } catch (error) {
        errors.push(`Batch write failed: ${String(error)}`);
      }
    }

    await createAuditLog(
      auth.userId,
      'BULK_IMPORT',
      'AUTHLOG',
      'bulk',
      { imported, failed: items.length - imported }
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
    console.error('Error in auth logs bulk import:', error);
    return errorResponse(500, 'Internal server error');
  }
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const path = event.path || '';
  const method = event.httpMethod || 'GET';

  try {
    // GET /resources
    if (method === 'GET' && path === '/resources') {
      return await handleGetResources(event);
    }

    // POST /api/{tableIndex}/bulk
    const bulkMatch = path.match(/^\/api\/(\d+)\/bulk$/);
    if (method === 'POST' && bulkMatch) {
      const tableIndex = bulkMatch[1];
      switch (tableIndex) {
        case '0':
          return await handleResourcesBulk(event);
        case '1':
          return await handleUsersBulk(event);
        case '2':
          return await handleFacilitiesBulk(event);
        case '3':
          return await handleTimeSlotsBulk(event);
        case '4':
          return await handleReservationsBulk(event);
        case '5':
          return await handleLotteriesBulk(event);
        case '6':
          return await handlePaymentsBulk(event);
        case '7':
          return await handlePaymentHistoryBulk(event);
        case '8':
          return await handleCancellationsBulk(event);
        case '9':
          return await handleCategoriesBulk(event);
        case '10':
          return await handleAuthLogsBulk(event);
        default:
          return errorResponse(404, 'Table not found');
      }
    }

    return errorResponse(404, 'Endpoint not found');
  } catch (error) {
    console.error('Unhandled error:', error);
    return errorResponse(500, 'Internal server error');
  }
}