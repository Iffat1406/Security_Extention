import { randomUUID } from 'node:crypto';
import { PrismaClient, Role, type User } from '@prisma/client';

/**
 * Shared Prisma client for the test suite, against the same dev Postgres
 * container the app itself uses (docker-compose.yml). Phase 12 (§26.3)
 * formalises Testcontainers + per-test transaction rollback; until then,
 * each test generates unique random identifiers so runs don't collide.
 */
export const prisma = new PrismaClient();

export interface TestUserOverrides {
  role?: Role;
  isActive?: boolean;
}

export async function createTestUser(overrides: TestUserOverrides = {}): Promise<User> {
  const suffix = randomUUID();
  return prisma.user.create({
    data: {
      googleId: `test-google-${suffix}`,
      email: `test-${suffix}@example.com`,
      displayName: 'Test User',
      role: overrides.role ?? Role.USER,
      isActive: overrides.isActive ?? true,
    },
  });
}
