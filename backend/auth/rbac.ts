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
  const authHeader = event.headers['Authorization'] || '';
  const [, token] = authHeader.split(' ');

  let userId = 'unknown';
  let role: Role = 'viewer';

  if (token) {
    try {
      const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
      userId = decoded.userId || 'unknown';
      role = (decoded.role || 'viewer') as Role;
    } catch {
      role = 'viewer';
    }
  }

  return {
    userId,
    role,
    permissions: rolePermissions[role],
  };
}

export function requirePermission(
  context: RBACContext,
  permission: keyof RBACContext['permissions']
): boolean {
  return context.permissions[permission];
}

export function checkPermissionOrThrow(
  context: RBACContext,
  permission: keyof RBACContext['permissions']
): void {
  if (!requirePermission(context, permission)) {
    throw new ForbiddenError(`Permission denied: ${permission}`);
  }
}

export class ForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ForbiddenError';
  }
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}