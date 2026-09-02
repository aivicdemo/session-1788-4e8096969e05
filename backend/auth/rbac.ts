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

  if (!token) {
    throw new Error('Missing authorization token');
  }

  let decoded: { userId: string; role: Role };
  try {
    const payload = Buffer.from(token, 'base64').toString('utf-8');
    decoded = JSON.parse(payload);
  } catch {
    throw new Error('Invalid token format');
  }

  if (!decoded.userId || !decoded.role || !rolePermissions[decoded.role]) {
    throw new Error('Invalid token payload');
  }

  return {
    userId: decoded.userId,
    role: decoded.role,
    permissions: rolePermissions[decoded.role],
  };
}

export function requirePermission(
  context: RBACContext,
  permission: keyof RBACContext['permissions']
): void {
  if (!context.permissions[permission]) {
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