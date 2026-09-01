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

export function extractRBACContext(event: APIGatewayProxyEvent): RBACContext | null {
  const authHeader = event.headers['Authorization'] || event.headers['authorization'];
  if (!authHeader) {
    return null;
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }

  try {
    const token = parts[1];
    const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
    const role = (decoded.role || 'viewer') as Role;

    return {
      userId: decoded.userId || 'unknown',
      role,
      permissions: rolePermissions[role],
    };
  } catch {
    return null;
  }
}

export function requirePermission(
  context: RBACContext | null,
  permission: keyof RBACContext['permissions']
): boolean {
  if (!context) {
    return false;
  }
  return context.permissions[permission];
}

export function requireRole(context: RBACContext | null, ...roles: Role[]): boolean {
  if (!context) {
    return false;
  }
  return roles.includes(context.role);
}