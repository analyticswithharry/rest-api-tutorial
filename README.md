# REST API Lab

A fully-featured teaching REST API built with **Node.js + Express + SQLite**. Covers CRUD, JWT auth, RBAC, database queries, aggregations, stock management, reviews, and bulk operations.

## Quick Start

```bash
npm install
npm start
# → http://localhost:4101
```

Open `http://localhost:4101` in your browser for the **interactive UI**, `http://localhost:4101/concept.html` for concept notes, or `http://localhost:4101/practice.html` for hands-on practice tasks.

---

## Roles

| Role     | Read | Create / Update | Delete |
| -------- | ---- | --------------- | ------ |
| `viewer` | ✅   | ❌              | ❌     |
| `editor` | ✅   | ✅              | ❌     |
| `admin`  | ✅   | ✅              | ✅     |

---

## Database Schema (SQLite)

```
users       id, username, password_hash, role, created_at
categories  id, name, description, created_at
products    id, name, category, price, stock, description, created_at, updated_at
reviews     id, product_id, user_id, rating, comment, created_at
```

---

## Endpoints

### System

| Method | Path          | Auth | Description                                               |
| ------ | ------------- | ---- | --------------------------------------------------------- |
| GET    | `/api/health` | —    | Server health                                             |
| GET    | `/api/stats`  | —    | DB stats (counts, avg price, total stock, top categories) |

### Auth

| Method | Path                 | Auth  | Description            |
| ------ | -------------------- | ----- | ---------------------- |
| POST   | `/api/auth/register` | —     | Register → returns JWT |
| POST   | `/api/auth/login`    | —     | Login → returns JWT    |
| GET    | `/api/auth/me`       | any   | Current user profile   |
| GET    | `/api/users`         | admin | List all users         |

### Seed

| Method | Path        | Auth  | Description                             |
| ------ | ----------- | ----- | --------------------------------------- |
| POST   | `/api/seed` | admin | Insert 4 categories + 8 sample products |

### Categories

| Method | Path                  | Auth  | Description                    |
| ------ | --------------------- | ----- | ------------------------------ |
| GET    | `/api/categories`     | —     | List with product count (JOIN) |
| POST   | `/api/categories`     | admin | Create category                |
| DELETE | `/api/categories/:id` | admin | Delete category                |

### Products — CRUD

| Method | Path                | Auth    | Description                         |
| ------ | ------------------- | ------- | ----------------------------------- |
| GET    | `/api/products`     | —       | List with filters, sort, pagination |
| GET    | `/api/products/:id` | —       | Get single product                  |
| POST   | `/api/products`     | editor+ | Create product                      |
| PUT    | `/api/products/:id` | editor+ | Full replace                        |
| PATCH  | `/api/products/:id` | editor+ | Partial update                      |
| DELETE | `/api/products/:id` | admin   | Delete product                      |

**Query params for `GET /api/products`:**

| Param                     | Type         | Default      | Description               |
| ------------------------- | ------------ | ------------ | ------------------------- |
| `q`                       | string       | —            | Search name + description |
| `category`                | string       | —            | Filter by category        |
| `min_price` / `max_price` | number       | —            | Price range filter        |
| `min_stock` / `max_stock` | number       | —            | Stock range filter        |
| `sort`                    | string       | `created_at` | Sort field                |
| `order`                   | `asc`/`desc` | `desc`       | Sort direction            |
| `page`                    | number       | `1`          | Page number               |
| `limit`                   | number       | `10`         | Results per page (max 50) |

### Products — Advanced Queries

| Method | Path                            | Auth    | Description                                                       |
| ------ | ------------------------------- | ------- | ----------------------------------------------------------------- |
| GET    | `/api/products/search/advanced` | —       | Full text + price range + `in_stock` filter                       |
| GET    | `/api/products/aggregates`      | —       | GROUP BY category with min/max/avg price, total stock, avg rating |
| GET    | `/api/products/top-rated`       | —       | Products ranked by average review rating (JOIN)                   |
| GET    | `/api/products/low-stock`       | editor+ | Products at or below `?threshold` (default 20)                    |

### Stock Management

| Method | Path                        | Auth    | Description                                          |
| ------ | --------------------------- | ------- | ---------------------------------------------------- |
| POST   | `/api/products/:id/restock` | editor+ | Add `{ qty }` to stock                               |
| POST   | `/api/products/:id/destock` | editor+ | Remove `{ qty }` from stock (prevents going below 0) |

### Reviews

| Method | Path                        | Auth | Description                           |
| ------ | --------------------------- | ---- | ------------------------------------- |
| GET    | `/api/products/:id/reviews` | —    | List reviews with avg rating          |
| POST   | `/api/products/:id/reviews` | any  | Add review `{ rating: 1–5, comment }` |
| DELETE | `/api/reviews/:id`          | any  | Delete review (admin or own)          |

### Bulk Operations

| Method | Path                        | Auth  | Description                              |
| ------ | --------------------------- | ----- | ---------------------------------------- |
| POST   | `/api/products/bulk-create` | admin | Insert array (max 50) in SQL transaction |
| DELETE | `/api/products/bulk-delete` | admin | Delete by array of IDs                   |

---

## Example curl Workflow

```bash
# Register admin
curl -X POST http://localhost:4101/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret123","role":"admin"}'

# Login
TOKEN=$(curl -s -X POST http://localhost:4101/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret123"}' | \
  node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>console.log(JSON.parse(d).data.token))")

# Seed data
curl -X POST http://localhost:4101/api/seed \
  -H "Authorization: Bearer $TOKEN"

# List products filtered by category, sorted by price
curl "http://localhost:4101/api/products?category=electronics&sort=price&order=asc&limit=5"

# Restock product #1 by 50 units
curl -X POST http://localhost:4101/api/products/1/restock \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"qty":50}'

# Bulk create products
curl -X POST http://localhost:4101/api/products/bulk-create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"products":[{"name":"Widget A","category":"tools","price":9.99,"stock":100},{"name":"Widget B","category":"tools","price":14.99,"stock":50}]}'
```

---

## What You'll Learn

- REST architectural constraints and URL design
- HTTP methods — GET, POST, PUT, PATCH, DELETE
- JWT authentication and RBAC middleware
- SQLite CRUD with parameterised queries
- SQL JOINs, GROUP BY, aggregations, transactions
- Pagination, filtering, sorting patterns
- One-to-many relationships (products ↔ reviews)
- Atomic stock operations (prevent negative stock)
- Bulk operations inside SQL transactions
- Global error handling in Express
