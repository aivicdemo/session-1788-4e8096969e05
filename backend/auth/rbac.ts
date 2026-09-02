import { APIGatewayProxyEvent } from 'aws-lambda';

export type Role = 'admin' | 'operator' | 'viewer';

export interface AuthContext {
  userId: string;
  role: Role;
  email: string;
}

export const ROLE_PERMISSIONS: Record<Role, Set<string>> = {
  admin: new Set([
    'resources:read',
    'resources:create',
    'resources:update',
    'resources:delete',
    'resources:bulk',
    'users:read',
    'users:create',
    'users:update',
    'users:delete',
    'users:bulk',
    'facilities:read',
    'facilities:create',
    'facilities:update',
    'facilities:delete',
    'facilities:bulk',
    'timeslots:read',
    'timeslots:create',
    'timeslots:update',
    'timeslots:delete',
    'timeslots:bulk',
    'reservations:read',
    'reservations:create',
    'reservations:update',
    'reservations:delete',
    'reservations:bulk',
    'lotteries:read',
    'lotteries:create',
    'lotteries:update',
    'lotteries:delete',
    'lotteries:bulk',
    'payments:read',
    'payments:create',
    'payments:update',
    'payments:delete',
    'payments:bulk',
    'paymenthistories:read',
    'paymenthistories:create',
    'paymenthistories:update',
    'paymenthistories:delete',
    'paymenthistories:bulk',
    'cancellations:read',
    'cancellations:create',
    'cancellations:update',
    'cancellations:delete',
    'cancellations:bulk',
    'categories:read',
    'categories:create',
    'categories:update',
    'categories:delete',
    'categories:bulk',
    'authlogs:read',
    'authlogs:create',
    'authlogs:bulk',
    'auditlogs:read',
  ]),
  operator: new Set([
    'resources:read',
    'resources:create',
    'resources:update',
    'resources:bulk',
    'users:read',
    'users:create',
    'users:update',
    'facilities:read',
    'facilities:create',
    'facilities:update',
    'facilities:bulk',
    'timeslots:read',
    'timeslots:create',
    'timeslots:update',
    'timeslots:bulk',
    'reservations:read',
    'reservations:create',
    'reservations:update',
    'reservations:bulk',
    'lotteries:read',
    'lotteries:create',
    'lotteries:update',
    'lotteries:bulk',
    'payments:read',
    'payments:create',
    'payments:update',
    'payments:bulk',
    'paymenthistories:read',
    'paymenthistories:create',
    'paymenthistories:bulk',
    'cancellations:read',
    'cancellations:create',
    'cancellations:update',
    'cancellations:bulk',
    'categories:read',
    'categories:create',
    'categories:update',
    'categories:bulk',
    'authlogs:read',
    'authlogs:create',
    'auditlogs:read',
  ]),
  viewer: new Set([
    'resources:read',
    'users:read',
    'facilities:read',
    'timeslots:read',
    'reservations:read',
    'lotteries:read',
    'payments:read',
    'paymenthistories:read',
    'cancellations:read',
    'categories:read',
    'authlogs:read',
  ]),
};

export function extractAuthContext(event: APIGatewayProxyEvent): AuthContext {
  const authHeader = event.headers.Authorization || event.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '');
  
  try {
    const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    return {
      userId: decoded.sub || decoded.userId || 'unknown',
      role: (decoded.role || 'viewer') as Role,
      email: decoded.email || 'unknown@example.com',
    };
  } catch {
    return {
      userId: 'unknown',
      role: 'viewer',
      email: 'unknown@example.com',
    };
  }
}

export function hasPermission(auth: AuthContext, permission: string): boolean {
  const permissions = ROLE_PERMISSIONS[auth.role];
  return permissions.has(permission);
}

export function requirePermission(auth: AuthContext, permission: string): void {
  if (!hasPermission(auth, permission)) {
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