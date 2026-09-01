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
import { extractRBACContext, requirePermission, requireRole } from './rbac';

const tableName = process.env.MAIN_TABLE || 'SecurityIncidentTable';
const client = new DynamoDBClient({ region: 'ap-northeast-1' });
const docClient = DynamoDBDocumentClient.from(client);

interface AuditLogEntry {
  pk: string;
  sk: string;
  eventType: string;
  userId?: string;
  targetResourceType: string;
  targetResourceId?: string;
  operationContent: string;
  changeBefore?: string;
  changeAfter?: string;
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
  changeBefore?: string;
  changeAfter?: string;
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
  statusBefore: string;
  statusAfter: string;
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
  targetPeriodStart: number;
  targetPeriodEnd: number;
  discoveredVulnerabilityCount?: number;
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
  validFlag: boolean;
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
  publicationDate?: number;
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
  | 'VULNERABILITY_MASTER';

const tableIndexMap: Record<string, TableType> = {
  '0': 'USER',
  '1': 'VULNERABILITY',
  '2': 'SCAN_RESULT',
  '3': 'AUDIT_LOG',
  '4': 'TICKET',
  '5': 'STATUS_HISTORY',
  '6': 'IMPACT_ANALYSIS',
  '7': 'REPORT',
  '8': 'ASSET',
  '9': 'PERMISSION',
  '10': 'VULNERABILITY_MASTER',
};

function getPkSk(tableType: TableType): { pk: string; sk: string } {
  const baseMap: Record<TableType, { pk: string; sk: string }> = {
    USER: { pk: 'USER', sk: 'USER' },
    VULNERABILITY: { pk: 'VULNERABILITY', sk: 'VULNERABILITY' },
    SCAN_RESULT: { pk: 'SCAN_RESULT', sk: 'SCAN_RESULT' },
    AUDIT_LOG: { pk: 'AUDIT', sk: 'AUDIT' },
    TICKET: { pk: 'TICKET', sk: 'TICKET' },
    STATUS_HISTORY: { pk: 'STATUS_HISTORY', sk: 'STATUS_HISTORY' },
    IMPACT_ANALYSIS: { pk: 'IMPACT_ANALYSIS', sk: 'IMPACT_ANALYSIS' },
    REPORT: { pk: 'REPORT', sk: 'REPORT' },
    ASSET: { pk: 'ASSET', sk: 'ASSET' },
    PERMISSION: { pk: 'PERMISSION', sk: 'PERMISSION' },
    VULNERABILITY_MASTER: { pk: 'VULNERABILITY_MASTER', sk: 'VULNERABILITY_MASTER' },
  };
  return baseMap[tableType];
}

async function createAuditLog(
  eventType: string,
  userId: string | undefined,
  targetResourceType: string,
  targetResourceId: string | undefined,
  operationContent: string,
  changeBefore?: string,
  changeAfter?: string,
  ipAddress?: string,
  sessionId?: string,
  severity: string = 'medium',
  status: string = 'completed'
): Promise<void> {
  const auditLogId = randomUUID();
  const now = Date.now();
  const { pk, sk } = getPkSk('AUDIT_LOG');

  const auditLog: AuditLog = {
    pk,
    sk: `${sk}#${auditLogId}`,
    auditLogId,
    eventType,
    userId,
    targetResourceType,
    targetResourceId,
    operationContent,
    changeBefore,
    changeAfter,
    ipAddress,
    sessionId,
    severity,
    status,
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
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const rbacContext = extractRBACContext(event);

  if (!rbacContext || !requirePermission(rbacContext, 'auditLogView')) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Forbidden' }),
    };
  }

  try {
    const { pk, sk } = getPkSk('ASSET');
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': pk,
        },
      })
    );

    const items = (result.Items || []) as SystemAsset[];

    await createAuditLog(
      'RESOURCE_LIST_VIEW',
      rbacContext.userId,
      'ASSET',
      undefined,
      `Retrieved ${items.length} system assets`,
      undefined,
      undefined,
      event.requestContext?.identity?.sourceIp,
      event.requestContext?.requestId,
      'low',
      'completed'
    );

    return {
      statusCode: 200,
      body: JSON.stringify({
        resources: items,
        count: items.length,
      }),
    };
  } catch (error) {
    console.error('Error retrieving resources:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal Server Error' }),
    };
  }
}

async function handleBulkImport(
  event: APIGatewayProxyEvent,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  const rbacContext = extractRBACContext(event);

  if (!rbacContext || !requireRole(rbacContext, 'admin', 'operator')) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Forbidden' }),
    };
  }

  const tableType = tableIndexMap[tableIndex];
  if (!tableType) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Invalid table index' }),
    };
  }

  try {
    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items) || items.length === 0) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'items must be a non-empty array' }),
      };
    }

    const { pk, sk } = getPkSk(tableType);
    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      ...item,
      pk,
      sk: `${sk}#${randomUUID()}`,
      id: randomUUID(),
      createdAt: now,
      updatedAt: now,
      createdBy: rbacContext.userId,
      updatedBy: rbacContext.userId,
    }));

    const chunks: Record<string, unknown>[][] = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    let failed = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      const requestItems: BatchWriteItemCommandInput['RequestItems'] = {
        [tableName]: chunk.map((item) => ({
          PutRequest: {
            Item: Object.entries(item).reduce(
              (acc, [key, value]) => {
                if (value === null || value === undefined) {
                  return acc;
                }
                if (typeof value === 'string') {
                  acc[key] = { S: value };
                } else if (typeof value === 'number') {
                  acc[key] = { N: value.toString() };
                } else if (typeof value === 'boolean') {
                  acc[key] = { BOOL: value };
                } else if (Array.isArray(value)) {
                  acc[key] = { SS: value.map((v) => String(v)) };
                } else {
                  acc[key] = { S: JSON.stringify(value) };
                }
                return acc;
              },
              {} as Record<string, unknown>
            ),
          },
        })),
      };

      try {
        await client.send(new BatchWriteItemCommand({ RequestItems: requestItems }));
        imported += chunk.length;
      } catch (error) {
        failed += chunk.length;
        errors.push(`Batch write failed: ${String(error)}`);
      }
    }

    await createAuditLog(
      'BULK_IMPORT',
      rbacContext.userId,
      tableType,
      undefined,
      `Bulk imported ${imported} items to ${tableType}`,
      undefined,
      JSON.stringify({ imported, failed, totalItems: items.length }),
      event.requestContext?.identity?.sourceIp,
      event.requestContext?.requestId,
      'high',
      'completed'
    );

    return {
      statusCode: 200,
      body: JSON.stringify({
        imported,
        failed,
        errors,
      }),
    };
  } catch (error) {
    console.error('Error in bulk import:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal Server Error' }),
    };
  }
}

async function handleGetUsers(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const rbacContext = extractRBACContext(event);

  if (!rbacContext || !requirePermission(rbacContext, 'auditLogView')) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Forbidden' }),
    };
  }

  try {
    const { pk, sk } = getPkSk('USER');
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': pk,
        },
      })
    );

    const items = (result.Items || []) as User[];

    return {
      statusCode: 200,
      body: JSON.stringify({
        users: items,
        count: items.length,
      }),
    };
  } catch (error) {
    console.error('Error retrieving users:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal Server Error' }),
    };
  }
}

async function handleGetVulnerabilities(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const rbacContext = extractRBACContext(event);

  if (!rbacContext || !requirePermission(rbacContext, 'auditLogView')) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Forbidden' }),
    };
  }

  try {
    const { pk, sk } = getPkSk('VULNERABILITY');
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': pk,
        },
      })
    );

    const items = (result.Items || []) as Vulnerability[];

    return {
      statusCode: 200,
      body: JSON.stringify({
        vulnerabilities: items,
        count: items.length,
      }),
    };
  } catch (error) {
    console.error('Error retrieving vulnerabilities:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal Server Error' }),
    };
  }
}

async function handleGetScanResults(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const rbacContext = extractRBACContext(event);

  if (!rbacContext || !requirePermission(rbacContext, 'auditLogView')) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Forbidden' }),
    };
  }

  try {
    const { pk, sk } = getPkSk('SCAN_RESULT');
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': pk,
        },
      })
    );

    const items = (result.Items || []) as VulnerabilityScanResult[];

    return {
      statusCode: 200,
      body: JSON.stringify({
        scanResults: items,
        count: items.length,
      }),
    };
  } catch (error) {
    console.error('Error retrieving scan results:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal Server Error' }),
    };
  }
}

async function handleGetAuditLogs(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const rbacContext = extractRBACContext(event);

  if (!rbacContext || !requirePermission(rbacContext, 'auditLogView')) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Forbidden' }),
    };
  }

  try {
    const { pk, sk } = getPkSk('AUDIT_LOG');
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': pk,
        },
      })
    );

    const items = (result.Items || []) as AuditLog[];

    return {
      statusCode: 200,
      body: JSON.stringify({
        auditLogs: items,
        count: items.length,
      }),
    };
  } catch (error) {
    console.error('Error retrieving audit logs:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal Server Error' }),
    };
  }
}

async function handleGetTickets(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const rbacContext = extractRBACContext(event);

  if (!rbacContext || !requirePermission(rbacContext, 'incidentRespond')) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Forbidden' }),
    };
  }

  try {
    const { pk, sk } = getPkSk('TICKET');
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': pk,
        },
      })
    );

    const items = (result.Items || []) as VulnerabilityResponseTicket[];

    return {
      statusCode: 200,
      body: JSON.stringify({
        tickets: items,
        count: items.length,
      }),
    };
  } catch (error) {
    console.error('Error retrieving tickets:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal Server Error' }),
    };
  }
}

async function handleGetReports(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const rbacContext = extractRBACContext(event);

  if (!rbacContext || !requirePermission(rbacContext, 'reportGenerate')) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Forbidden' }),
    };
  }

  try {
    const { pk, sk } = getPkSk('REPORT');
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': pk,
        },
      })
    );

    const items = (result.Items || []) as Report[];

    return {
      statusCode: 200,
      body: JSON.stringify({
        reports: items,
        count: items.length,
      }),
    };
  } catch (error) {
    console.error('Error retrieving reports:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal Server Error' }),
    };
  }
}

async function handleGetPermissions(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const rbacContext = extractRBACContext(event);

  if (!rbacContext || !requireRole(rbacContext, 'admin')) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Forbidden' }),
    };
  }

  try {
    const { pk, sk } = getPkSk('PERMISSION');
    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'pk = :pk',
        ExpressionAttributeValues: {
          ':pk': pk,
        },
      })
    );

    const items = (result.Items || []) as PermissionSetting[];

    return {
      statusCode: 200,
      body: JSON.stringify({
        permissions: items,
        count: items.length,
      }),
    };
  } catch (error) {
    console.error('Error retrieving permissions:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal Server Error' }),
    };
  }
}

export const handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  const path = event.path || '';
  const method = event.httpMethod || 'GET';

  console.log(`${method} ${path}`);

  if (method === 'GET' && path === '/resources') {
    return handleGetResources(event);
  }

  if (method === 'GET' && path === '/users') {
    return handleGetUsers(event);
  }

  if (method === 'GET' && path === '/vulnerabilities') {
    return handleGetVulnerabilities(event);
  }

  if (method === 'GET' && path === '/scan-results') {
    return handleGetScanResults(event);
  }

  if (method === 'GET' && path === '/audit-logs') {
    return handleGetAuditLogs(event);
  }

  if (method === 'GET' && path === '/tickets') {
    return handleGetTickets(event);
  }

  if (method === 'GET' && path === '/reports') {
    return handleGetReports(event);
  }

  if (method === 'GET' && path === '/permissions') {
    return handleGetPermissions(event);
  }

  const bulkImportMatch = path.match(/^\/api\/(\d+)\/bulk$/);
  if (method === 'POST' && bulkImportMatch) {
    const tableIndex = bulkImportMatch[1];
    return handleBulkImport(event, tableIndex);
  }

  return {
    statusCode: 404,
    body: JSON.stringify({ error: 'Not Found' }),
  };
};