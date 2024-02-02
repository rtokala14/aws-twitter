import { int, text, mysqlTableCreator } from 'drizzle-orm/mysql-core';
const mysqlTable = mysqlTableCreator((name) => `aws-twitter_${name}`);
export const users = mysqlTable('users', {
  id: int('id').primaryKey().autoincrement(),
  name: text('name').notNull(),
});
