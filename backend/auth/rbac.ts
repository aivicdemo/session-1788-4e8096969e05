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
  },
  operator: {
    auditLogView: true,
    vulnerabilityManage: true,
    incidentRespond: true,
    reportGenerate: true,
    assetManage: true,
    permissionDelete: false,
  },
  viewer: {
    auditLogView: true,
    vulnerabilityManage: false,
    incidentRespond: false,
    reportGenerate: false,
    assetManage: false,
    permissionDelete: false,
  },
};

export function extractRBACContext(event: APIGatewayProxyEvent): RBACContext {
  const authHeader = event.headers['Authorization'] || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    throw new Error('Missing or invalid Authorization header');
  }

  const [userId, role] = token.split(':');

  if (!userId || !role || !['admin', 'operator', 'viewer'].includes(role)) {
    throw new Error('Invalid token format');
  }

  return {
    userId,
    role: role as Role,
    permissions: rolePermissions[role as Role],
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

export function requireRole(context: RBACContext, ...roles: Role[]): void {
  if (!roles.includes(context.role)) {
    throw new Error(`Forbidden: role ${context.role} not allowed`);
  }
}