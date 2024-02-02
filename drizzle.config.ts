import type { Config } from 'drizzle-kit'

export default {
	schema: "./src/drizzle/schema.ts",
	driver: "mysql2",
	dbCredentials: {
		uri: process.env.DATABASE_URL as string,
	},
	tablesFilter: ["aws-twitter_*"],
} satisfies Config;
