import { Hono } from 'hono'
import { db } from './drizzle'
import { users } from './drizzle/schema'
import { FC, Fragment } from 'hono/jsx'

const app = new Hono()

const HTML: FC = (props) => { 
  return (
    <html lang='en'>
      <head>
        <title> Twitter with Hono and Htmx </title>
        
        <script src='https://unpkg.com/htmx.org@latest' />
        
      </head>
      <body>
        {props.children}

      </body>
    </html>
  )
}

app.get('/', (c) => c.html(
  <HTML>
    <h1 hx-get="/getUser" hx-target="#users-target" hx-trigger="load">User List</h1>
    <div id="users-target" hx-get="/getUser" hx-swap="innerHTML transition:true" hx-trigger="newUser from:body"/>
    <h2>Add Users</h2>
    <form hx-post="/addUser" hx-swap='none' >
      <input name='userName' placeholder='John Doe..' />
      <button type='submit'>Submit</button>
    </form>
  </HTML>
))

app.post('/addUser', async (c) => {
  const req = await c.req.formData()
  const userName = req.get('userName') 
  try {
    const res = await db.insert(users).values({
      name: userName as string 
    })
    c.header('HX-Trigger','newUser')
    c.status(200)
    return c.text("User Added")

  } catch {
    return c.text("Failed to Create", 400)
  }
})

app.get('/getUser', async (c) => {
  const userList = await db.select().from(users)
  return c.html(
    <Fragment>
      {
        userList.map(user => <div>
          <a href={`/user/${user.id}`}>{user.name}</a>
        </div>)
      }
    </Fragment>
  );
})

export default {
  port: 3000,
  fetch: app.fetch,
}
