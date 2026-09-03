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
  const roleHeader = event.headers['X-User-Role'] || 'viewer';
  const userIdHeader = event.headers['X-User-Id'] || 'unknown';

  const role = (roleHeader as Role) || 'viewer';
  const permissions = rolePermissions[role] || rolePermissions.viewer;

  return {
    userId: userIdHeader,
    role,
    permissions,
  };
}

export function requirePermission(
  context: RBACContext,
  permission: keyof RBACContext['permissions']
): boolean {
  return context.permissions[permission];
}

export function requireRole(context: RBACContext, allowedRoles: Role[]): boolean {
  return allowedRoles.includes(context.role);
}