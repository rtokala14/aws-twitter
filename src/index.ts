import { Hono } from 'hono'
import { db } from './drizzle'
import { users } from './drizzle/schema'

const app = new Hono()

app.get('/', (c) => {
  return c.text('Hello Hono!')
})

app.get('/test', (c) => {
  return c.json({ res: "This Works I guess" })
})

const res = await db.select().from(users); 
console.log(res)

export default {
  port: 3000,
  fetch: app.fetch,
}
