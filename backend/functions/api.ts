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
import { extractRBACContext, requirePermission, requireRole } from './rbac';

const client = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
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

interface User {
  pk: string;
  sk: string;
  userId: string;
  userName: string;
  email: string;
  department?: string;
  position?: string;
  role: string;
  status: string;
  lastLoginAt?: number;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
  updatedBy?: string;
}

interface Vulnerability {
  pk: string;
  sk: string;
  vulnerabilityId: string;
  vulnerabilityName: string;
  description?: string;
  cveIdentifier?: string;
  severityLevel: string;
  cvssScore?: number;
  affectedSystem?: string;
  detectedAt: number;
  responseStatus: string;
  responseDueDate?: number;
  responseContent?: string;
  responseCompletedAt?: number;
  assignee?: string;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
  updatedBy: string;
}

interface VulnerabilityScanResult {
  pk: string;
  sk: string;
  scanResultId: string;
  vulnerabilityId: string;
  scanExecutedAt: number;
  targetResource: string;
  severityLevel: string;
  detectionStatus: string;
  detailInfo?: string;
  recommendedResponse?: string;
  responseDueDate?: number;
  assigneeId?: string;
  createdAt: number;
  updatedAt: number;
  createdById: string;
}

interface AuditLog {
  pk: string;
  sk: string;
  auditLogId: string;
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

interface VulnerabilityResponseTicket {
  pk: string;
  sk: string;
  ticketId: string;
  vulnerabilityId: string;
  scanResultId?: string;
  ticketTitle: string;
  description?: string;
  status: string;
  priority: string;
  assigneeId?: string;
  dueDate?: number;
  completedAt?: number;
  createdAt: number;
  createdById: string;
  updatedAt: number;
  updatedById: string;
}

interface ResponseStatusHistory {
  pk: string;
  sk: string;
  historyId: string;
  ticketId: string;
  beforeStatus: string;
  afterStatus: string;
  responseContent?: string;
  responderId: string;
  createdAt: number;
  remarks?: string;
}

interface ImpactAnalysis {
  pk: string;
  sk: string;
  analysisId: string;
  vulnerabilityId: string;
  scanResultId?: string;
  ticketId?: string;
  affectedUserCount: number;
  affectedSystemCount: number;
  impactLevel: string;
  impactExplanation?: string;
  responsePriority: string;
  analysisStatus: string;
  analysisCompletedAt?: number;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
  updatedBy?: string;
}

interface Report {
  pk: string;
  sk: string;
  reportId: string;
  reportName: string;
  reportType: string;
  periodStartDate: number;
  periodEndDate: number;
  foundVulnerabilityCount?: number;
  completedVulnerabilityCount?: number;
  incidentCount?: number;
  severityAggregation?: string;
  reportContent?: string;
  status: string;
  createdById: string;
  approvedById?: string;
  distributionList?: string;
  createdAt: number;
  updatedAt: number;
  approvedAt?: number;
  distributedAt?: number;
}

interface SystemAsset {
  pk: string;
  sk: string;
  assetId: string;
  assetName: string;
  assetType: string;
  ipAddress?: string;
  hostName?: string;
  osType?: string;
  osVersion?: string;
  ownerDepartment: string;
  responsible?: string;
  importanceLevel: string;
  scanTargetFlag: boolean;
  auditTargetFlag: boolean;
  operatingStatus: string;
  deploymentDate?: number;
  decommissionDate?: number;
  remarks?: string;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
  updatedBy: string;
}

interface PermissionSetting {
  pk: string;
  sk: string;
  permissionId: string;
  userId: string;
  role: string;
  auditLogViewPermission: boolean;
  vulnerabilityManagePermission: boolean;
  incidentRespondPermission: boolean;
  reportGeneratePermission: boolean;
  assetManagePermission: boolean;
  permissionDeletePermission: boolean;
  enabledFlag: boolean;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
  updatedBy: string;
  remarks?: string;
}

interface VulnerabilityMaster {
  pk: string;
  sk: string;
  vulnerabilityId: string;
  cveId: string;
  vulnerabilityName: string;
  description: string;
  cvssScore: number;
  severity: string;
  attackVector?: string;
  impactScope?: string;
  publishedAt?: number;
  referenceUrl?: string;
  responsePriority: string;
  status: string;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}

type TableType =
  | 'USER'
  | 'VULNERABILITY'
  | 'SCAN_RESULT'
  | 'AUDIT_LOG'
  | 'TICKET'
  | 'STATUS_HISTORY'
  | 'IMPACT_ANALYSIS'
  | 'REPORT'
  | 'ASSET'
  | 'PERMISSION'
  | 'VULN_MASTER';

const tableIndexMap: Record<number, TableType> = {
  0: 'USER',
  1: 'VULNERABILITY',
  2: 'SCAN_RESULT',
  3: 'AUDIT_LOG',
  4: 'TICKET',
  5: 'STATUS_HISTORY',
  6: 'IMPACT_ANALYSIS',
  7: 'REPORT',
  8: 'ASSET',
  9: 'PERMISSION',
  10: 'VULN_MASTER',
};

function getPkSk(tableType: TableType, id: string): { pk: string; sk: string } {
  return {
    pk: tableType,
    sk: id,
  };
}

async function createAuditLog(
  eventType: string,
  userId: string,
  targetResourceType: string,
  targetResourceId: string | undefined,
  operationContent: string,
  beforeValue: string | undefined,
  afterValue: string | undefined,
  severity: string,
  ipAddress?: string,
  sessionId?: string
): Promise<void> {
  const auditLogId = randomUUID();
  const now = Date.now();
  const { pk, sk } = getPkSk('AUDIT_LOG', auditLogId);

  const auditLog: AuditLog = {
    pk,
    sk,
    auditLogId,
    eventType,
    userId,
    targetResourceType,
    targetResourceId,
    operationContent,
    beforeValue,
    afterValue,
    ipAddress,
    sessionId,
    severity,
    status: 'UNPROCESSED',
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

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const rbacContext = extractRBACContext(event);
    const method = event.httpMethod;
    const path = event.path;
    const pathParameters = event.pathParameters || {};
    const queryStringParameters = event.queryStringParameters || {};
    const body = event.body ? JSON.parse(event.body) : {};

    // GET /resources
    if (method === 'GET' && path === '/resources') {
      if (!requirePermission(rbacContext, 'auditLogView')) {
        return errorResponse(403, 'Forbidden: Insufficient permissions');
      }

      const result = await docClient.send(
        new ScanCommand({
          TableName: TABLE_NAME,
          FilterExpression: 'begins_with(pk, :pk)',
          ExpressionAttributeValues: {
            ':pk': 'RESOURCE',
          },
        })
      );

      return successResponse(200, {
        resources: result.Items || [],
        count: result.Count || 0,
      });
    }

    // POST /api/{tableIndex}/bulk
    const bulkMatch = path.match(/^\/api\/(\d+)\/bulk$/);
    if (method === 'POST' && bulkMatch) {
      if (!requireRole(rbacContext, ['admin', 'operator'])) {
        return errorResponse(403, 'Forbidden: Only admin/operator can bulk import');
      }

      const tableIndex = parseInt(bulkMatch[1], 10);
      const tableType = tableIndexMap[tableIndex];

      if (!tableType) {
        return errorResponse(400, 'Invalid table index');
      }

      const { items } = body as { items: Record<string, unknown>[] };

      if (!Array.isArray(items)) {
        return errorResponse(400, 'Items must be an array');
      }

      const now = Date.now();
      const processedItems = items.map((item) => {
        const id = randomUUID();
        const { pk, sk } = getPkSk(tableType, id);
        return {
          ...item,
          pk,
          sk,
          id,
          createdAt: now,
          updatedAt: now,
          createdBy: rbacContext.userId,
        };
      });

      const chunks = [];
      for (let i = 0; i < processedItems.length; i += 25) {
        chunks.push(processedItems.slice(i, i + 25));
      }

      let imported = 0;
      const errors: string[] = [];

      for (const chunk of chunks) {
        const requests = chunk.map((item) => ({
          PutRequest: {
            Item: item,
          },
        }));

        try {
          await docClient.send(
            new BatchWriteCommand({
              RequestItems: {
                [TABLE_NAME]: requests,
              },
            })
          );
          imported += chunk.length;
        } catch (err) {
          const errorMsg = err instanceof Error ? err.message : String(err);
          errors.push(errorMsg);
        }
      }

      await createAuditLog(
        'BULK_IMPORT',
        rbacContext.userId,
        tableType,
        undefined,
        `Bulk imported ${imported} items to ${tableType}`,
        undefined,
        undefined,
        'HIGH',
        event.requestContext?.identity?.sourceIp
      );

      return successResponse(200, {
        imported,
        failed: items.length - imported,
        errors,
      });
    }

    // GET /api/{tableIndex}/{id}
    const getMatch = path.match(/^\/api\/(\d+)\/([a-f0-9-]+)$/);
    if (method === 'GET' && getMatch) {
      if (!requirePermission(rbacContext, 'auditLogView')) {
        return errorResponse(403, 'Forbidden: Insufficient permissions');
      }

      const tableIndex = parseInt(getMatch[1], 10);
      const id = getMatch[2];
      const tableType = tableIndexMap[tableIndex];

      if (!tableType) {
        return errorResponse(400, 'Invalid table index');
      }

      const { pk, sk } = getPkSk(tableType, id);

      const result = await docClient.send(
        new GetCommand({
          TableName: TABLE_NAME,
          Key: { pk, sk },
        })
      );

      if (!result.Item) {
        return errorResponse(404, 'Resource not found');
      }

      return successResponse(200, result.Item);
    }

    // POST /api/{tableIndex}
    const postMatch = path.match(/^\/api\/(\d+)$/);
    if (method === 'POST' && postMatch) {
      if (!requirePermission(rbacContext, 'vulnerabilityManage')) {
        return errorResponse(403, 'Forbidden: Insufficient permissions');
      }

      const tableIndex = parseInt(postMatch[1], 10);
      const tableType = tableIndexMap[tableIndex];

      if (!tableType) {
        return errorResponse(400, 'Invalid table index');
      }

      const id = randomUUID();
      const now = Date.now();
      const { pk, sk } = getPkSk(tableType, id);

      const item = {
        ...body,
        pk,
        sk,
        id,
        createdAt: now,
        updatedAt: now,
        createdBy: rbacContext.userId,
      };

      await docClient.send(
        new PutCommand({
          TableName: TABLE_NAME,
          Item: item,
        })
      );

      await createAuditLog(
        'CREATE',
        rbacContext.userId,
        tableType,
        id,
        `Created new ${tableType} record`,
        undefined,
        JSON.stringify(item),
        'MEDIUM',
        event.requestContext?.identity?.sourceIp
      );

      return successResponse(201, item);
    }

    // PUT /api/{tableIndex}/{id}
    const putMatch = path.match(/^\/api\/(\d+)\/([a-f0-9-]+)$/);
    if (method === 'PUT' && putMatch) {
      if (!requirePermission(rbacContext, 'vulnerabilityManage')) {
        return errorResponse(403, 'Forbidden: Insufficient permissions');
      }

      const tableIndex = parseInt(putMatch[1], 10);
      const id = putMatch[2];
      const tableType = tableIndexMap[tableIndex];

      if (!tableType) {
        return errorResponse(400, 'Invalid table index');
      }

      const { pk, sk } = getPkSk(tableType, id);

      const existing = await docClient.send(
        new GetCommand({
          TableName: TABLE_NAME,
          Key: { pk, sk },
        })
      );

      if (!existing.Item) {
        return errorResponse(404, 'Resource not found');
      }

      const now = Date.now();
      const updated = {
        ...existing.Item,
        ...body,
        pk,
        sk,
        updatedAt: now,
        updatedBy: rbacContext.userId,
      };

      await docClient.send(
        new PutCommand({
          TableName: TABLE_NAME,
          Item: updated,
        })
      );

      await createAuditLog(
        'UPDATE',
        rbacContext.userId,
        tableType,
        id,
        `Updated ${tableType} record`,
        JSON.stringify(existing.Item),
        JSON.stringify(updated),
        'MEDIUM',
        event.requestContext?.identity?.sourceIp
      );

      return successResponse(200, updated);
    }

    // DELETE /api/{tableIndex}/{id}
    const deleteMatch = path.match(/^\/api\/(\d+)\/([a-f0-9-]+)$/);
    if (method === 'DELETE' && deleteMatch) {
      if (!requireRole(rbacContext, ['admin'])) {
        return errorResponse(403, 'Forbidden: Only admin can delete');
      }

      const tableIndex = parseInt(deleteMatch[1], 10);
      const id = deleteMatch[2];
      const tableType = tableIndexMap[tableIndex];

      if (!tableType) {
        return errorResponse(400, 'Invalid table index');
      }

      const { pk, sk } = getPkSk(tableType, id);

      const existing = await docClient.send(
        new GetCommand({
          TableName: TABLE_NAME,
          Key: { pk, sk },
        })
      );

      if (!existing.Item) {
        return errorResponse(404, 'Resource not found');
      }

      await docClient.send(
        new DeleteCommand({
          TableName: TABLE_NAME,
          Key: { pk, sk },
        })
      );

      await createAuditLog(
        'DELETE',
        rbacContext.userId,
        tableType,
        id,
        `Deleted ${tableType} record`,
        JSON.stringify(existing.Item),
        undefined,
        'HIGH',
        event.requestContext?.identity?.sourceIp
      );

      return successResponse(200, { message: 'Deleted successfully' });
    }

    return errorResponse(404, 'Endpoint not found');
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    console.error('Error:', errorMsg);
    return errorResponse(500, 'Internal server error');
  }
}