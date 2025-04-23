# jwt-auth-practice-server

This is a simple Node.js and Express-based API built for **learning authentication and authorization concepts**.  
It covers user registration, login with JWT token issuance, route protection with middleware, role-based access control, and basic rate limiting.  
This project uses in-memory user storage, making it ideal for beginners who want to understand the flow without using a database.

---

## Tech Stack

- `express` — Web server
- `bcryptjs` — Password hashing
- `jsonwebtoken` — JWT token creation & verification
- `dotenv` — Environment variable management
- `express-rate-limit` — Basic request throttling

---

## Getting Started

1. **Install dependencies**

```bash
npm install
```

2. **Set up `.env`**

Create a `.env` file in the root with:

```env
JWT_SECRECT=yourSuperSecretKey
```

3. **Run the server**

```bash
node index.js
```

The server will start on: `http://localhost:3000`

---

## API Endpoints

### `/register` — POST

Register a new user.

```json
{
  "username": "john",
  "password": "1234",
  "role": "admin" // optional, defaults to "user"
}
```

---

### `/login` — POST

Login with existing credentials. Returns a JWT token.

```json
{
  "username": "john",
  "password": "1234"
}
```

Response:

```json
{
  "token": "<JWT_TOKEN>"
}
```

---

### `/admin-only` — GET

Protected route. Requires:

- Valid JWT token
- User must have role `"admin"`

**Headers:**

```
Authorization: Bearer <JWT_TOKEN>
```

---

### `/user-or-admin` — GET

Protected route. Allows:

- `"user"` or `"admin"` roles

**Headers:**

```
Authorization: Bearer <JWT_TOKEN>
```

---

## Rate Limiting

- Max 2 requests per minute per IP for `/register` and `/login`
- Exceeding this limit returns:

```json
{
  "msg": "Too many requests, please try again later.."
}
```

---

## Notes

- This server uses an **in-memory array** (`users[]`) to store users. It resets every time the server restarts.
- For real applications, integrate a persistent database like MongoDB, PostgreSQL, etc.
- All logic is kept in a single file (`index.js`) to make it easy to follow. You can refactor it into modules as a next step.

---

## Learning Goals

This project helps understand:

- Hashing passwords securely
- Issuing and verifying JWTs
- Middleware for authentication and authorization
- Role-based access control
- Request rate limiting
