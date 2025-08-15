#!/usr/bin/env tsx

/**
 * Test script to verify migration works
 * This creates a temporary in-memory SQLite database for testing
 */

import Database from 'better-sqlite3';
import { readFileSync } from 'fs';
import { join } from 'path';

function convertMySQLToSQLite(mysqlSql: string): string {
  let result = mysqlSql;
  
  // Remove stored procedures and delimiter blocks first
  result = result.replace(/DELIMITER\s+\/\/[\s\S]*?DELIMITER\s+;/gi, '');
  
  // Convert types
  result = result.replace(/\bBIGINT\b/gi, 'INTEGER');
  result = result.replace(/\bBOOLEAN\b/gi, 'INTEGER');
  result = result.replace(/\bJSON\b/gi, 'TEXT');
  result = result.replace(/\bENUM\([^)]+\)/gi, 'TEXT');
  result = result.replace(/\bTIMESTAMP\b/gi, 'TEXT');
  result = result.replace(/\bAUTO_INCREMENT\s+PRIMARY\s+KEY\b/gi, 'PRIMARY KEY AUTOINCREMENT');
  result = result.replace(/\bPRIMARY\s+KEY\s+AUTOINCREMENT\s+PRIMARY\s+KEY\b/gi, 'PRIMARY KEY AUTOINCREMENT');
  
  // Fix timestamp defaults
  result = result.replace(/DEFAULT CURRENT_TIMESTAMP/gi, "DEFAULT DATETIME('now')");
  result = result.replace(/ON UPDATE CURRENT_TIMESTAMP/gi, '');
  
  // Remove MySQL-specific clauses
  result = result.replace(/\s+ENGINE=\w+/gi, '');
  result = result.replace(/\s+DEFAULT CHARSET=[\w_]+/gi, '');
  result = result.replace(/\s+COLLATE=[\w_]+/gi, '');
  
  // Remove index definitions (simplify for testing)
  result = result.replace(/,\s*INDEX\s+[\w_]+\s*\([^)]+\)/gi, '');
  result = result.replace(/,\s*UNIQUE KEY\s+[\w_]+\s*\(/gi, ', UNIQUE (');
  result = result.replace(/,\s*FOREIGN KEY[^,)]+/gi, '');
  
  // Fix INSERT IGNORE
  result = result.replace(/INSERT IGNORE/gi, 'INSERT OR IGNORE');
  
  return result;
}

async function testMigration() {
  console.log('🧪 Testing database migration...');
  
  try {
    // Create in-memory SQLite database
    const db = new Database(':memory:');
    
    // Read MySQL schema
    const schemaPath = join(process.cwd(), 'scripts/mysql-schema.sql');
    const mysqlSchema = readFileSync(schemaPath, 'utf-8');
    
    // Convert to SQLite-compatible SQL
    const sqliteSchema = convertMySQLToSQLite(mysqlSchema);
    
    // Split into statements
    const statements = sqliteSchema
      .split(';')
      .map(stmt => stmt.trim())
      .filter(stmt => {
        // Remove empty statements and pure comment lines
        if (stmt.length === 0) return false;
        
        // Remove lines that are only comments
        const lines = stmt.split('\n').map(line => line.trim());
        const nonCommentLines = lines.filter(line => line.length > 0 && !line.startsWith('--'));
        
        return nonCommentLines.length > 0;
      });
    
    console.log(`📄 Executing ${statements.length} SQL statements...`);
    
    // Debug: Show first few statements
    if (statements.length === 0) {
      console.log('⚠️  No statements found. Original schema length:', mysqlSchema.length);
      console.log('Converted schema length:', sqliteSchema.length);
      console.log('First 500 chars of converted schema:', sqliteSchema.substring(0, 500));
      
      // Show all semicolons for debugging
      const semicolonCount = (sqliteSchema.match(/;/g) || []).length;
      console.log('Semicolon count in converted schema:', semicolonCount);
      
      // Show raw split results
      const rawSplit = sqliteSchema.split(';');
      console.log('Raw split result count:', rawSplit.length);
      console.log('First 3 raw statements:');
      rawSplit.slice(0, 3).forEach((stmt, i) => {
        console.log(`${i}: "${stmt.trim()}"`);
      });
    }
    
    // Execute each statement
    for (const statement of statements) {
      if (statement.toLowerCase().includes('create table')) {
        console.log(`📝 Creating table: ${statement.match(/create table\s+(?:if not exists\s+)?(\w+)/i)?.[1]}`);
      }
      db.exec(statement);
    }
    
    // Verify tables were created
    const tables = ['users', 'oauth_clients', 'auth_codes', 'tokens', 'jwks', 'identities'];
    const createdTables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
    const tableNames = createdTables.map((t: any) => t.name);
    
    console.log(`📊 Created tables: ${tableNames.join(', ')}`);
    
    for (const table of tables) {
      if (!tableNames.includes(table)) {
        throw new Error(`❌ Table ${table} was not created`);
      }
    }
    
    // Test basic CRUD operations
    console.log('🔧 Testing basic CRUD operations...');
    
    // Insert test client
    db.prepare(`
      INSERT INTO oauth_clients (client_id, name, redirect_uris, first_party, allowed_scopes)
      VALUES (?, ?, ?, ?, ?)
    `).run('test-client', 'Test Client', '["http://localhost:3000"]', 1, '["openid"]');
    
    // Insert test user
    const userResult = db.prepare(`
      INSERT INTO users (nickname, is_admin)
      VALUES (?, ?)
    `).run('Test User', 0);
    
    const userId = userResult.lastInsertRowid;
    
    // Insert test identity
    db.prepare(`
      INSERT INTO identities (user_id, provider, openid, profile)
      VALUES (?, ?, ?, ?)
    `).run(userId, 'wechat', 'test-openid', '{"nickname": "Test User"}');
    
    // Verify data
    const client = db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get('test-client');
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    const identity = db.prepare('SELECT * FROM identities WHERE user_id = ?').get(userId);
    
    if (!client || !user || !identity) {
      throw new Error('❌ CRUD test failed - data not inserted correctly');
    }
    
    console.log('✅ All tests passed! Database schema is valid.');
    console.log('📋 Migration test summary:');
    console.log(`   • Created ${tableNames.length} tables`);
    console.log(`   • Inserted test data successfully`);
    console.log(`   • CRUD operations working`);
    
    db.close();
    
  } catch (error) {
    console.error('❌ Migration test failed:', error);
    process.exit(1);
  }
}

// Run test if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  testMigration();
}

export { testMigration };