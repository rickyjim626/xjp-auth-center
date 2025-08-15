import { DatabaseAdapter } from '../db/DatabaseAdapter.js';
import { UsersRepo } from './users.repo.js';
import { IdentitiesRepo } from './identities.repo.js';
import { OAuthRepo } from './oauth.repo.js';
import { JWKRepo } from './jwk.repo.js';

/**
 * Repository 工厂类
 * 统一管理所有数据访问层实例
 */
export class RepositoryFactory {
  private static instance: RepositoryFactory;
  
  public readonly users: UsersRepo;
  public readonly identities: IdentitiesRepo;
  public readonly oauth: OAuthRepo;
  public readonly jwk: JWKRepo;

  private constructor(db: DatabaseAdapter) {
    this.users = new UsersRepo(db);
    this.identities = new IdentitiesRepo(db);
    this.oauth = new OAuthRepo(db);
    this.jwk = new JWKRepo(db);
  }

  static initialize(db: DatabaseAdapter): RepositoryFactory {
    if (!RepositoryFactory.instance) {
      RepositoryFactory.instance = new RepositoryFactory(db);
    }
    return RepositoryFactory.instance;
  }

  static getInstance(): RepositoryFactory {
    if (!RepositoryFactory.instance) {
      throw new Error('Repository factory not initialized. Call initialize() first.');
    }
    return RepositoryFactory.instance;
  }
}

// 便捷导出
export function getRepos(): RepositoryFactory {
  return RepositoryFactory.getInstance();
}

export * from './users.repo.js';
export * from './identities.repo.js';
export * from './oauth.repo.js';
export * from './jwk.repo.js';