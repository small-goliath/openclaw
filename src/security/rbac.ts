/**
 * 역할 기반 접근 제어 (RBAC) 구현
 * SOC 2 CC6.2 준수
 */

import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("security/rbac");

/**
 * 역할 정의
 */
export type Role = "admin" | "manager" | "user" | "viewer" | "guest";

/**
 * 권한 정의
 */
export type Permission =
  // 사용자 관리
  | "users:create"
  | "users:read"
  | "users:update"
  | "users:delete"
  // 역할 관리
  | "roles:manage"
  // 에이전트 관리
  | "agents:create"
  | "agents:read"
  | "agents:update"
  | "agents:delete"
  // 메모리 관리
  | "memory:read"
  | "memory:write"
  | "memory:delete"
  // 설정 관리
  | "settings:read"
  | "settings:write"
  // 감사 로그
  | "audit:read"
  // DSR 처리
  | "dsr:manage"
  // 시스템 관리
  | "system:manage"
  | "system:shutdown";

/**
 * 역할별 기본 권한 매핑
 */
export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  admin: [
    "users:create",
    "users:read",
    "users:update",
    "users:delete",
    "roles:manage",
    "agents:create",
    "agents:read",
    "agents:update",
    "agents:delete",
    "memory:read",
    "memory:write",
    "memory:delete",
    "settings:read",
    "settings:write",
    "audit:read",
    "dsr:manage",
    "system:manage",
    "system:shutdown",
  ],
  manager: [
    "users:create",
    "users:read",
    "users:update",
    "agents:create",
    "agents:read",
    "agents:update",
    "agents:delete",
    "memory:read",
    "memory:write",
    "memory:delete",
    "settings:read",
    "settings:write",
    "audit:read",
    "dsr:manage",
  ],
  user: [
    "users:read",
    "agents:create",
    "agents:read",
    "agents:update",
    "agents:delete",
    "memory:read",
    "memory:write",
    "settings:read",
  ],
  viewer: [
    "users:read",
    "agents:read",
    "memory:read",
    "settings:read",
  ],
  guest: [
    "agents:read",
    "memory:read",
  ],
};

/**
 * 사용자 역할 할당
 */
export interface UserRoleAssignment {
  userId: string;
  role: Role;
  assignedBy: string;
  assignedAt: number;
  expiresAt?: number;
  context?: Record<string, unknown>;
}

/**
 * RBAC 정책
 */
export interface RBACPolicy {
  allow?: Permission[];
  deny?: Permission[];
  resourceFilter?: {
    agents?: string[];
    users?: string[];
    channels?: string[];
  };
}

/**
 * 접근 확인 결과
 */
export interface AccessCheckResult {
  allowed: boolean;
  reason?: string;
  missingPermissions?: Permission[];
}

// 메모리 저장소 (실제 구현에서는 데이터베이스 사용)
const userRoles = new Map<string, UserRoleAssignment>();
const customPolicies = new Map<string, RBACPolicy>();

/**
 * 사용자에게 역할 할당
 */
export function assignRole(assignment: Omit<UserRoleAssignment, "assignedAt">): UserRoleAssignment {
  const fullAssignment: UserRoleAssignment = {
    ...assignment,
    assignedAt: Date.now(),
  };

  userRoles.set(assignment.userId, fullAssignment);

  log.info("Role assigned", {
    userId: assignment.userId,
    role: assignment.role,
    assignedBy: assignment.assignedBy,
  });

  return fullAssignment;
}

/**
 * 사용자 역할 조회
 */
export function getUserRole(userId: string): UserRoleAssignment | undefined {
  return userRoles.get(userId);
}

/**
 * 사용자 역할 제거
 */
export function revokeRole(userId: string, revokedBy: string): boolean {
  const assignment = userRoles.get(userId);
  if (!assignment) {
    return false;
  }

  userRoles.delete(userId);

  log.info("Role revoked", {
    userId,
    role: assignment.role,
    revokedBy,
  });

  return true;
}

/**
 * 역할의 권한 목록 조회
 */
export function getRolePermissions(role: Role): Permission[] {
  return [...(ROLE_PERMISSIONS[role] || [])];
}

/**
 * 사용자의 권한 목록 조회
 */
export function getUserPermissions(userId: string): Permission[] {
  const assignment = userRoles.get(userId);
  if (!assignment) {
    return [];
  }

  // 역할 기본 권한
  const permissions = new Set(getRolePermissions(assignment.role));

  // 커스텀 정책 적용
  const policy = customPolicies.get(userId);
  if (policy) {
    // 추가 권한
    if (policy.allow) {
      for (const perm of policy.allow) {
        permissions.add(perm);
      }
    }
    // 제거 권한
    if (policy.deny) {
      for (const perm of policy.deny) {
        permissions.delete(perm);
      }
    }
  }

  // 만료 체크
  if (assignment.expiresAt && Date.now() > assignment.expiresAt) {
    log.warn("Role assignment expired", { userId, role: assignment.role });
    return [];
  }

  return Array.from(permissions);
}

/**
 * 권한 확인
 */
export function hasPermission(userId: string, permission: Permission): boolean {
  const permissions = getUserPermissions(userId);
  return permissions.includes(permission);
}

/**
 * 다중 권한 확인
 */
export function hasPermissions(userId: string, permissions: Permission[]): boolean {
  const userPerms = getUserPermissions(userId);
  return permissions.every((perm) => userPerms.includes(perm));
}

/**
 * 접근 확인 (상세 결과)
 */
export function checkAccess(
  userId: string,
  requiredPermissions: Permission | Permission[]
): AccessCheckResult {
  const required = Array.isArray(requiredPermissions)
    ? requiredPermissions
    : [requiredPermissions];

  const userPerms = getUserPermissions(userId);
  const missing = required.filter((perm) => !userPerms.includes(perm));

  if (missing.length === 0) {
    return { allowed: true };
  }

  return {
    allowed: false,
    reason: `Missing permissions: ${missing.join(", ")}`,
    missingPermissions: missing,
  };
}

/**
 * 리소스 접근 확인
 */
export function checkResourceAccess(
  userId: string,
  resourceType: "agent" | "user" | "channel",
  resourceId: string,
  permission: Permission
): AccessCheckResult {
  // 기본 권한 확인
  const access = checkAccess(userId, permission);
  if (!access.allowed) {
    return access;
  }

  // 커스텀 정책의 리소스 필터 확인
  const assignment = userRoles.get(userId);
  const policy = customPolicies.get(userId);

  if (policy?.resourceFilter) {
    const allowedResources =
      resourceType === "agent"
        ? policy.resourceFilter.agents
        : resourceType === "user"
          ? policy.resourceFilter.users
          : policy.resourceFilter.channels;

    if (allowedResources && !allowedResources.includes(resourceId)) {
      return {
        allowed: false,
        reason: `Access denied to ${resourceType} ${resourceId}`,
      };
    }
  }

  // 자신의 리소스는 항상 접근 가능
  if (resourceType === "user" && resourceId === userId) {
    return { allowed: true };
  }

  return { allowed: true };
}

/**
 * 미들웨어용 접근 제어 함수
 */
export function requirePermission(...permissions: Permission[]) {
  return (userId: string): AccessCheckResult => {
    return checkAccess(userId, permissions);
  };
}

/**
 * 관리자 권한 확인
 */
export function isAdmin(userId: string): boolean {
  const assignment = userRoles.get(userId);
  return assignment?.role === "admin";
}

/**
 * 커스텀 정책 설정
 */
export function setCustomPolicy(userId: string, policy: RBACPolicy): void {
  customPolicies.set(userId, policy);

  log.info("Custom policy set", {
    userId,
    allow: policy.allow,
    deny: policy.deny,
  });
}

/**
 * 커스텀 정책 제거
 */
export function removeCustomPolicy(userId: string): void {
  customPolicies.delete(userId);
  log.info("Custom policy removed", { userId });
}

/**
 * 모든 역할 목록 조회
 */
export function listRoles(): Array<{
  role: Role;
  permissions: Permission[];
  userCount: number;
}> {
  const roleCounts = new Map<Role, number>();
  for (const assignment of userRoles.values()) {
    roleCounts.set(assignment.role, (roleCounts.get(assignment.role) || 0) + 1);
  }

  return (Object.keys(ROLE_PERMISSIONS) as Role[]).map((role) => ({
    role,
    permissions: ROLE_PERMISSIONS[role],
    userCount: roleCounts.get(role) || 0,
  }));
}

/**
 * 역할별 사용자 목록 조회
 */
export function getUsersByRole(role: Role): UserRoleAssignment[] {
  return Array.from(userRoles.values()).filter((a) => a.role === role);
}

/**
 * RBAC 통계
 */
export function getRBACStats(): {
  totalUsers: number;
  roleDistribution: Record<Role, number>;
  customPolicies: number;
} {
  const roleDistribution: Record<Role, number> = {
    admin: 0,
    manager: 0,
    user: 0,
    viewer: 0,
    guest: 0,
  };

  for (const assignment of userRoles.values()) {
    roleDistribution[assignment.role]++;
  }

  return {
    totalUsers: userRoles.size,
    roleDistribution,
    customPolicies: customPolicies.size,
  };
}

/**
 * 권한 문자열 파싱
 */
export function parsePermission(permissionString: string): Permission | null {
  const validPermissions: Permission[] = [
    "users:create",
    "users:read",
    "users:update",
    "users:delete",
    "roles:manage",
    "agents:create",
    "agents:read",
    "agents:update",
    "agents:delete",
    "memory:read",
    "memory:write",
    "memory:delete",
    "settings:read",
    "settings:write",
    "audit:read",
    "dsr:manage",
    "system:manage",
    "system:shutdown",
  ];

  return validPermissions.includes(permissionString as Permission)
    ? (permissionString as Permission)
    : null;
}

/**
 * 역할 문자열 파싱
 */
export function parseRole(roleString: string): Role | null {
  const validRoles: Role[] = ["admin", "manager", "user", "viewer", "guest"];
  return validRoles.includes(roleString as Role) ? (roleString as Role) : null;
}
