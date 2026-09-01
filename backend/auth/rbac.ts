import { APIGatewayProxyEvent } from 'aws-lambda';

export type Role = 'admin' | 'operator' | 'viewer';

export interface RBACContext {
  userId: string;
  role: Role;
  permissions: {
    auditLogView: boolean;
    vulnerabilityManage: boolean;
    incidentRespond: boolean;
    reportGenerate: boolean;
    assetManage: boolean;
    permissionDelete: boolean;
    bulkImport: boolean;
  };
}

const rolePermissions: Record<Role, RBACContext['permissions']> = {
  admin: {
    auditLogView: true,
    vulnerabilityManage: true,
    incidentRespond: true,
    reportGenerate: true,
    assetManage: true,
    permissionDelete: true,
    bulkImport: true,
  },
  operator: {
    auditLogView: true,
    vulnerabilityManage: true,
    incidentRespond: true,
    reportGenerate: true,
    assetManage: true,
    permissionDelete: false,
    bulkImport: true,
  },
  viewer: {
    auditLogView: true,
    vulnerabilityManage: false,
    incidentRespond: false,
    reportGenerate: false,
    assetManage: false,
    permissionDelete: false,
    bulkImport: false,
  },
};

export function extractRBACContext(event: APIGatewayProxyEvent): RBACContext {
  const authHeader = event.headers?.Authorization || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    throw new Error('Missing or invalid Authorization header');
  }

  const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
  const role = (decoded.role || 'viewer') as Role;

  if (!rolePermissions[role]) {
    throw new Error(`Invalid role: ${role}`);
  }

  return {
    userId: decoded.userId || 'unknown',
    role,
    permissions: rolePermissions[role],
  };
}

export function requirePermission(
  context: RBACContext,
  permission: keyof RBACContext['permissions']
): void {
  if (!context.permissions[permission]) {
    throw new Error(`Forbidden: ${permission} not allowed for role ${context.role}`);
  }
}