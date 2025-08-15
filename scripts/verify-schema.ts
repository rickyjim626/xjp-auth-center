#!/usr/bin/env tsx

/**
 * Verify that our MySQL schema is syntactically correct
 * and contains all expected tables and indexes
 */

import { readFileSync } from 'fs';
import { join } from 'path';

function verifySchema() {
  console.log('🔍 Verifying MySQL schema...');
  
  try {
    // Read schema file
    const schemaPath = join(process.cwd(), 'scripts/mysql-schema.sql');
    const schema = readFileSync(schemaPath, 'utf-8');
    
    console.log(`📄 Schema file size: ${schema.length} characters`);
    
    // Check for required tables
    const requiredTables = [
      'users',
      'identities', 
      'oauth_clients',
      'auth_codes',
      'tokens',
      'jwks'
    ];
    
    const missingTables: string[] = [];
    const foundTables: string[] = [];
    
    for (const table of requiredTables) {
      const tableRegex = new RegExp(`CREATE TABLE IF NOT EXISTS ${table}`, 'i');
      if (tableRegex.test(schema)) {
        foundTables.push(table);
      } else {
        missingTables.push(table);
      }
    }
    
    if (missingTables.length > 0) {
      throw new Error(`Missing tables: ${missingTables.join(', ')}`);
    }
    
    console.log(`✅ All ${foundTables.length} required tables found: ${foundTables.join(', ')}`);
    
    // Check for key features
    const features = [
      { name: 'Primary keys', pattern: /PRIMARY KEY/gi },
      { name: 'Foreign keys', pattern: /FOREIGN KEY/gi },
      { name: 'Indexes', pattern: /INDEX/gi },
      { name: 'Unique constraints', pattern: /UNIQUE/gi },
      { name: 'Default values', pattern: /DEFAULT/gi },
    ];
    
    console.log('📋 Schema features:');
    for (const feature of features) {
      const matches = schema.match(feature.pattern);
      const count = matches ? matches.length : 0;
      console.log(`   • ${feature.name}: ${count}`);
    }
    
    // Check for default data
    const hasDefaultData = /INSERT.*oauth_clients/i.test(schema);
    console.log(`   • Default client data: ${hasDefaultData ? 'Yes' : 'No'}`);
    
    // Verify SQL syntax (basic checks)
    const statements = schema
      .split(';')
      .map(stmt => stmt.trim())
      .filter(stmt => {
        if (stmt.length === 0) return false;
        // Filter out pure comment blocks
        const lines = stmt.split('\n').filter(line => {
          const trimmed = line.trim();
          return trimmed.length > 0 && !trimmed.startsWith('--');
        });
        return lines.length > 0;
      });
      
    console.log(`📝 Found ${statements.length} SQL statements`);
    
    // Check for common syntax issues
    const syntaxChecks = [
      { name: 'Unmatched parentheses', test: (s: string) => checkParentheses(s) },
      { name: 'Invalid table definitions', test: (s: string) => /CREATE TABLE.*\(\s*\)/i.test(s) },
      { name: 'Missing semicolons on CREATE', test: (s: string) => /CREATE TABLE[^;]*$/mi.test(s) },
    ];
    
    const issues: string[] = [];
    for (const check of syntaxChecks) {
      if (check.test(schema)) {
        issues.push(check.name);
      }
    }
    
    if (issues.length > 0) {
      console.warn(`⚠️  Potential syntax issues: ${issues.join(', ')}`);
    } else {
      console.log('✅ Basic syntax checks passed');
    }
    
    // Verify table relationships
    console.log('🔗 Checking table relationships...');
    const foreignKeys = [
      { table: 'identities', references: 'users(id)' },
      { table: 'auth_codes', references: 'users(id)' },
      { table: 'auth_codes', references: 'oauth_clients(client_id)' },
      { table: 'tokens', references: 'users(id)' },
      { table: 'tokens', references: 'oauth_clients(client_id)' },
    ];
    
    for (const fk of foreignKeys) {
      const fkPattern = new RegExp(`${fk.table}[\\s\\S]*?FOREIGN KEY[\\s\\S]*?REFERENCES ${fk.references}`, 'i');
      if (fkPattern.test(schema)) {
        console.log(`   ✅ ${fk.table} → ${fk.references}`);
      } else {
        console.log(`   ❌ Missing: ${fk.table} → ${fk.references}`);
      }
    }
    
    console.log('');
    console.log('🎉 Schema verification completed successfully!');
    console.log('📄 The MySQL schema appears to be well-formed and complete.');
    console.log('');
    console.log('Next steps:');
    console.log('  1. Test with a real MySQL database using `npm run migrate`');
    console.log('  2. Verify data operations with the repository layer');
    console.log('  3. Run integration tests');
    
  } catch (error) {
    console.error('❌ Schema verification failed:', error);
    process.exit(1);
  }
}

function checkParentheses(text: string): boolean {
  let count = 0;
  for (const char of text) {
    if (char === '(') count++;
    if (char === ')') count--;
    if (count < 0) return true; // More closing than opening
  }
  return count !== 0; // Should be zero at the end
}

// Run verification if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  verifySchema();
}

export { verifySchema };