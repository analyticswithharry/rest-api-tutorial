// ============================================================
// REST API LAB
// Full implementation: SQLite, JWT auth, RBAC, CRUD, search
// Port: 4101  (override with PORT env var)
// Start: npm install && npm start
// ============================================================

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();

// ── Config ─────────────────────────────────────────────────
const app = express();
const PORT = Number(process.env.PORT || 4101);
const JWT_SECRET = process.env.JWT_SECRET || "lab01_dev_secret_change_in_prod";
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || "2h";
const VALID_ROLES = new Set(["viewer", "editor", "admin"]);

// ── Middleware ──────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── Database setup ──────────────────────────────────────────
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new sqlite3.Database(path.join(dataDir, "lab01.db"));

// Promise wrappers so we can use async/await
const run = (sql, p = []) =>
  new Promise((res, rej) =>
    db.run(sql, p, function (e) {
      e ? rej(e) : res(this);
    }),
  );
const get = (sql, p = []) =>
  new Promise((res, rej) =>
    db.get(sql, p, (e, row) => {
      e ? rej(e) : res(row);
    }),
  );
const all = (sql, p = []) =>
  new Promise((res, rej) =>
    db.all(sql, p, (e, rows) => {
      e ? rej(e) : res(rows);
    }),
  );

// Create tables on first run
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK(role IN ('viewer','editor','admin')),
    created_at    TEXT    DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS categories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    category    TEXT    NOT NULL,
    price       REAL    NOT NULL CHECK(price >= 0),
    stock       INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
    description TEXT    DEFAULT '',
    created_at  TEXT    DEFAULT CURRENT_TIMESTAMP,
    updated_at  TEXT    DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS reviews (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    rating     INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
    comment    TEXT    DEFAULT '',
    created_at TEXT    DEFAULT CURRENT_TIMESTAMP
  )`);
});

// ── Auth helpers ────────────────────────────────────────────
const hashPassword = (pw) => {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
  return `${salt}:${hash}`;
};
const verifyPassword = (pw, stored) => {
  const [salt, original] = String(stored).split(":");
  if (!salt || !original) return false;
  const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(original), Buffer.from(hash));
};
const signToken = (user) =>
  jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES },
  );

const authenticate = (req, res, next) => {
  const token = (req.headers.authorization || "")
    .replace(/^Bearer\s+/i, "")
    .trim();
  if (!token)
    return res
      .status(401)
      .json({
        success: false,
        error: { code: "UNAUTHORIZED", message: "Token required" },
      });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res
      .status(401)
      .json({
        success: false,
        error: { code: "UNAUTHORIZED", message: "Invalid or expired token" },
      });
  }
};

const requireRole =
  (...roles) =>
  (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role))
      return res
        .status(403)
        .json({
          success: false,
          error: {
            code: "FORBIDDEN",
            message: `Requires role: ${roles.join(" or ")}`,
          },
        });
    next();
  };

// ── Validation helpers ──────────────────────────────────────
const has = (obj, k) => Object.prototype.hasOwnProperty.call(obj, k);

const validateProduct = (body, partial = false) => {
  const err = [];
  if (!partial || has(body, "name"))
    if (typeof body.name !== "string" || body.name.trim().length < 2)
      err.push("'name' must be at least 2 characters");
  if (!partial || has(body, "category"))
    if (typeof body.category !== "string" || body.category.trim().length < 2)
      err.push("'category' must be at least 2 characters");
  if (!partial || has(body, "price"))
    if (typeof body.price !== "number" || body.price < 0)
      err.push("'price' must be a non-negative number");
  if (has(body, "stock") && (!Number.isInteger(body.stock) || body.stock < 0))
    err.push("'stock' must be a non-negative integer");
  return err;
};

// ── ROUTES: System ──────────────────────────────────────────

// GET /api/health
app.get("/api/health", (req, res) =>
  res.json({
    success: true,
    lab: "rest-api",
    status: "running",
    timestamp: new Date().toISOString(),
  }),
);

// GET /api/stats  — aggregated database statistics
app.get("/api/stats", async (req, res, next) => {
  try {
    const [u, c, p, avg, stock, topCat] = await Promise.all([
      get("SELECT COUNT(*) as n FROM users"),
      get("SELECT COUNT(*) as n FROM categories"),
      get("SELECT COUNT(*) as n FROM products"),
      get("SELECT ROUND(AVG(price),2) as v FROM products"),
      get("SELECT COALESCE(SUM(stock),0) as v FROM products"),
      all(
        "SELECT category, COUNT(*) as count FROM products GROUP BY category ORDER BY count DESC LIMIT 5",
      ),
    ]);
    res.json({
      success: true,
      data: {
        users: u.n,
        categories: c.n,
        products: p.n,
        avgPrice: avg.v || 0,
        totalStock: stock.v,
        topCategories: topCat,
      },
    });
  } catch (err) {
    next(err);
  }
});

// ── ROUTES: Auth ────────────────────────────────────────────

// POST /api/auth/register
app.post("/api/auth/register", async (req, res, next) => {
  try {
    const username = String(req.body.username || "")
      .trim()
      .toLowerCase();
    const password = String(req.body.password || "");
    const role = String(req.body.role || "viewer")
      .trim()
      .toLowerCase();

    if (username.length < 3)
      return res
        .status(400)
        .json({
          success: false,
          error: {
            code: "VALIDATION_ERROR",
            message: "'username' must be at least 3 characters",
          },
        });
    if (password.length < 8)
      return res
        .status(400)
        .json({
          success: false,
          error: {
            code: "VALIDATION_ERROR",
            message: "'password' must be at least 8 characters",
          },
        });
    if (!VALID_ROLES.has(role))
      return res
        .status(400)
        .json({
          success: false,
          error: {
            code: "VALIDATION_ERROR",
            message: "'role' must be viewer, editor, or admin",
          },
        });
    if (await get("SELECT id FROM users WHERE username = ?", [username]))
      return res
        .status(409)
        .json({
          success: false,
          error: { code: "CONFLICT", message: "Username already taken" },
        });

    const r = await run(
      "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
      [username, hashPassword(password), role],
    );
    const user = await get(
      "SELECT id, username, role, created_at FROM users WHERE id = ?",
      [r.lastID],
    );
    res
      .status(201)
      .json({ success: true, data: { user, token: signToken(user) } });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/login
app.post("/api/auth/login", async (req, res, next) => {
  try {
    const username = String(req.body.username || "")
      .trim()
      .toLowerCase();
    const password = String(req.body.password || "");
    if (!username || !password)
      return res
        .status(400)
        .json({
          success: false,
          error: {
            code: "VALIDATION_ERROR",
            message: "username and password required",
          },
        });

    const user = await get("SELECT * FROM users WHERE username = ?", [
      username,
    ]);
    if (!user || !verifyPassword(password, user.password_hash))
      return res
        .status(401)
        .json({
          success: false,
          error: { code: "UNAUTHORIZED", message: "Invalid credentials" },
        });

    res.json({
      success: true,
      data: {
        user: { id: user.id, username: user.username, role: user.role },
        token: signToken(user),
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/auth/me  (protected)
app.get("/api/auth/me", authenticate, (req, res) =>
  res.json({
    success: true,
    data: { id: req.user.id, username: req.user.username, role: req.user.role },
  }),
);

// GET /api/users  (admin only)
app.get(
  "/api/users",
  authenticate,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const rows = await all(
        "SELECT id, username, role, created_at FROM users ORDER BY created_at DESC",
      );
      res.json({ success: true, total: rows.length, data: rows });
    } catch (err) {
      next(err);
    }
  },
);

// ── ROUTES: Seed ────────────────────────────────────────────

// POST /api/seed  (admin only — inserts sample data)
app.post(
  "/api/seed",
  authenticate,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const existing = await get("SELECT COUNT(*) as n FROM products");
      if (existing.n > 0)
        return res.json({ success: true, message: "Already seeded. Skipped." });

      for (const name of ["electronics", "stationery", "lifestyle", "tools"])
        await run("INSERT OR IGNORE INTO categories (name) VALUES (?)", [name]);

      const products = [
        [
          "Laptop Stand",
          "electronics",
          39.99,
          50,
          "Adjustable ergonomic aluminium stand",
        ],
        [
          "Mechanical Keyboard",
          "electronics",
          79.99,
          30,
          "RGB backlit tactile switches",
        ],
        [
          "USB-C Hub",
          "electronics",
          24.99,
          100,
          "7-in-1 hub with 100W power delivery",
        ],
        ["Notebook A5", "stationery", 4.5, 200, "Hardcover lined A5 notebook"],
        ["Gel Pen Set", "stationery", 8.99, 150, "Pack of 12 colored gel pens"],
        [
          "Water Bottle",
          "lifestyle",
          12.75,
          80,
          "Insulated double-wall 1L bottle",
        ],
        ["Desk Mat", "lifestyle", 19.99, 60, "Extra-large microfiber desk mat"],
        [
          "Screwdriver Set",
          "tools",
          14.99,
          45,
          "Precision 32-bit magnetic driver set",
        ],
      ];
      for (const [name, category, price, stock, description] of products)
        await run(
          "INSERT INTO products (name, category, price, stock, description) VALUES (?,?,?,?,?)",
          [name, category, price, stock, description],
        );

      res
        .status(201)
        .json({ success: true, message: "Seeded 4 categories and 8 products" });
    } catch (err) {
      next(err);
    }
  },
);

// ── ROUTES: Categories ──────────────────────────────────────

// GET /api/categories
app.get("/api/categories", async (req, res, next) => {
  try {
    const rows = await all(`
      SELECT c.*, COUNT(p.id) as product_count
      FROM categories c
      LEFT JOIN products p ON p.category = c.name
      GROUP BY c.id
      ORDER BY c.name ASC
    `);
    res.json({ success: true, total: rows.length, data: rows });
  } catch (err) {
    next(err);
  }
});

// POST /api/categories  (admin)
app.post(
  "/api/categories",
  authenticate,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const name = String(req.body.name || "")
        .trim()
        .toLowerCase();
      const description = String(req.body.description || "").trim();
      if (name.length < 2)
        return res
          .status(400)
          .json({
            success: false,
            error: {
              code: "VALIDATION_ERROR",
              message: "'name' must be at least 2 characters",
            },
          });

      const r = await run(
        "INSERT INTO categories (name, description) VALUES (?,?)",
        [name, description],
      );
      res
        .status(201)
        .json({
          success: true,
          data: await get("SELECT * FROM categories WHERE id = ?", [r.lastID]),
        });
    } catch (err) {
      if (String(err.message).includes("UNIQUE"))
        return res
          .status(409)
          .json({
            success: false,
            error: { code: "CONFLICT", message: "Category already exists" },
          });
      next(err);
    }
  },
);

// DELETE /api/categories/:id  (admin)
app.delete(
  "/api/categories/:id",
  authenticate,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      if (!(await get("SELECT id FROM categories WHERE id = ?", [id])))
        return res
          .status(404)
          .json({
            success: false,
            error: { code: "NOT_FOUND", message: "Category not found" },
          });
      await run("DELETE FROM categories WHERE id = ?", [id]);
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  },
);

// ── ROUTES: Products ────────────────────────────────────────

// GET /api/products  — list with filter / search / sort / pagination
app.get("/api/products", async (req, res, next) => {
  try {
    const {
      category,
      q,
      min_price,
      max_price,
      min_stock,
      max_stock,
      sort = "created_at",
      order = "desc",
      page = "1",
      limit = "10",
    } = req.query;

    const validSort = [
      "id",
      "name",
      "category",
      "price",
      "stock",
      "created_at",
      "updated_at",
    ];
    const safeSort = validSort.includes(String(sort))
      ? String(sort)
      : "created_at";
    const safeOrder = String(order).toLowerCase() === "asc" ? "ASC" : "DESC";
    const pageNum = Math.max(parseInt(page) || 1, 1);
    const limitNum = Math.min(Math.max(parseInt(limit) || 10, 1), 50);
    const offset = (pageNum - 1) * limitNum;

    const clauses = [],
      params = [];
    if (category) {
      clauses.push("category = ?");
      params.push(category);
    }
    if (min_price !== undefined) {
      clauses.push("price >= ?");
      params.push(Number(min_price));
    }
    if (max_price !== undefined) {
      clauses.push("price <= ?");
      params.push(Number(max_price));
    }
    if (min_stock !== undefined) {
      clauses.push("stock >= ?");
      params.push(Number(min_stock));
    }
    if (max_stock !== undefined) {
      clauses.push("stock <= ?");
      params.push(Number(max_stock));
    }
    if (q) {
      clauses.push("(name LIKE ? OR description LIKE ?)");
      params.push(`%${q}%`, `%${q}%`);
    }

    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const total = (
      await get(`SELECT COUNT(*) as n FROM products ${where}`, params)
    ).n;
    const rows = await all(
      `SELECT * FROM products ${where} ORDER BY ${safeSort} ${safeOrder} LIMIT ? OFFSET ?`,
      [...params, limitNum, offset],
    );

    res.json({
      success: true,
      page: pageNum,
      limit: limitNum,
      total,
      totalPages: Math.ceil(total / limitNum),
      data: rows,
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/products/:id
app.get("/api/products/:id", async (req, res, next) => {
  try {
    const row = await get("SELECT * FROM products WHERE id = ?", [
      Number(req.params.id),
    ]);
    if (!row)
      return res
        .status(404)
        .json({
          success: false,
          error: { code: "NOT_FOUND", message: "Product not found" },
        });
    res.json({ success: true, data: row });
  } catch (err) {
    next(err);
  }
});

// POST /api/products  (editor or admin)
app.post(
  "/api/products",
  authenticate,
  requireRole("editor", "admin"),
  async (req, res, next) => {
    try {
      const errors = validateProduct(req.body);
      if (errors.length)
        return res
          .status(400)
          .json({
            success: false,
            error: { code: "VALIDATION_ERROR", message: errors.join("; ") },
          });

      const { name, category, price, stock = 0, description = "" } = req.body;
      const r = await run(
        "INSERT INTO products (name, category, price, stock, description) VALUES (?,?,?,?,?)",
        [
          name.trim(),
          category.trim().toLowerCase(),
          price,
          stock,
          String(description).trim(),
        ],
      );
      res
        .status(201)
        .location(`/api/products/${r.lastID}`)
        .json({
          success: true,
          data: await get("SELECT * FROM products WHERE id = ?", [r.lastID]),
        });
    } catch (err) {
      next(err);
    }
  },
);

// PUT /api/products/:id  — full replace (editor or admin)
app.put(
  "/api/products/:id",
  authenticate,
  requireRole("editor", "admin"),
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      if (!(await get("SELECT id FROM products WHERE id = ?", [id])))
        return res
          .status(404)
          .json({
            success: false,
            error: { code: "NOT_FOUND", message: "Product not found" },
          });

      const errors = validateProduct(req.body);
      if (errors.length)
        return res
          .status(400)
          .json({
            success: false,
            error: { code: "VALIDATION_ERROR", message: errors.join("; ") },
          });

      const { name, category, price, stock = 0, description = "" } = req.body;
      await run(
        "UPDATE products SET name=?,category=?,price=?,stock=?,description=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
        [
          name.trim(),
          category.trim().toLowerCase(),
          price,
          stock,
          String(description).trim(),
          id,
        ],
      );
      res.json({
        success: true,
        data: await get("SELECT * FROM products WHERE id = ?", [id]),
      });
    } catch (err) {
      next(err);
    }
  },
);

// PATCH /api/products/:id  — partial update (editor or admin)
app.patch(
  "/api/products/:id",
  authenticate,
  requireRole("editor", "admin"),
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      const existing = await get("SELECT * FROM products WHERE id = ?", [id]);
      if (!existing)
        return res
          .status(404)
          .json({
            success: false,
            error: { code: "NOT_FOUND", message: "Product not found" },
          });

      const errors = validateProduct(req.body, true);
      if (errors.length)
        return res
          .status(400)
          .json({
            success: false,
            error: { code: "VALIDATION_ERROR", message: errors.join("; ") },
          });

      const merged = {
        name: has(req.body, "name") ? req.body.name.trim() : existing.name,
        category: has(req.body, "category")
          ? req.body.category.trim().toLowerCase()
          : existing.category,
        price: has(req.body, "price") ? req.body.price : existing.price,
        stock: has(req.body, "stock") ? req.body.stock : existing.stock,
        description: has(req.body, "description")
          ? String(req.body.description).trim()
          : existing.description,
      };
      await run(
        "UPDATE products SET name=?,category=?,price=?,stock=?,description=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
        [
          merged.name,
          merged.category,
          merged.price,
          merged.stock,
          merged.description,
          id,
        ],
      );
      res.json({
        success: true,
        data: await get("SELECT * FROM products WHERE id = ?", [id]),
      });
    } catch (err) {
      next(err);
    }
  },
);

// DELETE /api/products/:id  (admin only)
app.delete(
  "/api/products/:id",
  authenticate,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      if (!(await get("SELECT id FROM products WHERE id = ?", [id])))
        return res
          .status(404)
          .json({
            success: false,
            error: { code: "NOT_FOUND", message: "Product not found" },
          });
      await run("DELETE FROM products WHERE id = ?", [id]);
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  },
);

// ── ROUTES: Reviews ─────────────────────────────────────────

// GET /api/products/:id/reviews  — all reviews for a product
app.get("/api/products/:id/reviews", async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!(await get("SELECT id FROM products WHERE id = ?", [id])))
      return res
        .status(404)
        .json({
          success: false,
          error: { code: "NOT_FOUND", message: "Product not found" },
        });

    const [reviews, agg] = await Promise.all([
      all(
        `SELECT r.id, r.rating, r.comment, r.created_at, u.username
           FROM reviews r JOIN users u ON u.id = r.user_id
           WHERE r.product_id = ? ORDER BY r.created_at DESC`,
        [id],
      ),
      get(
        "SELECT COUNT(*) as count, ROUND(AVG(rating),1) as avg FROM reviews WHERE product_id = ?",
        [id],
      ),
    ]);
    res.json({
      success: true,
      total: agg.count,
      avgRating: agg.avg || null,
      data: reviews,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/products/:id/reviews  (viewer, editor, admin)
app.post("/api/products/:id/reviews", authenticate, async (req, res, next) => {
  try {
    const productId = Number(req.params.id);
    if (!(await get("SELECT id FROM products WHERE id = ?", [productId])))
      return res
        .status(404)
        .json({
          success: false,
          error: { code: "NOT_FOUND", message: "Product not found" },
        });

    const rating = parseInt(req.body.rating);
    const comment = String(req.body.comment || "").trim();
    if (!Number.isInteger(rating) || rating < 1 || rating > 5)
      return res
        .status(400)
        .json({
          success: false,
          error: {
            code: "VALIDATION_ERROR",
            message: "'rating' must be an integer 1–5",
          },
        });

    const existing = await get(
      "SELECT id FROM reviews WHERE product_id = ? AND user_id = ?",
      [productId, req.user.id],
    );
    if (existing)
      return res
        .status(409)
        .json({
          success: false,
          error: {
            code: "CONFLICT",
            message: "You have already reviewed this product",
          },
        });

    const r = await run(
      "INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?,?,?,?)",
      [productId, req.user.id, rating, comment],
    );
    const review = await get(
      `SELECT r.id, r.rating, r.comment, r.created_at, u.username
       FROM reviews r JOIN users u ON u.id = r.user_id WHERE r.id = ?`,
      [r.lastID],
    );
    res.status(201).json({ success: true, data: review });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/reviews/:id  (admin or the review owner)
app.delete("/api/reviews/:id", authenticate, async (req, res, next) => {
  try {
    const review = await get("SELECT * FROM reviews WHERE id = ?", [
      Number(req.params.id),
    ]);
    if (!review)
      return res
        .status(404)
        .json({
          success: false,
          error: { code: "NOT_FOUND", message: "Review not found" },
        });
    if (req.user.role !== "admin" && review.user_id !== req.user.id)
      return res
        .status(403)
        .json({
          success: false,
          error: {
            code: "FORBIDDEN",
            message: "Cannot delete someone else's review",
          },
        });

    await run("DELETE FROM reviews WHERE id = ?", [review.id]);
    res.status(204).send();
  } catch (err) {
    next(err);
  }
});

// ── ROUTES: Advanced DB queries ─────────────────────────────

// GET /api/products/search/advanced  — full-text + price range + in-stock filter
app.get("/api/products/search/advanced", async (req, res, next) => {
  try {
    const { q = "", category, min_price, max_price, in_stock } = req.query;
    const clauses = ["1=1"],
      params = [];
    if (q) {
      clauses.push("(name LIKE ? OR description LIKE ?)");
      params.push(`%${q}%`, `%${q}%`);
    }
    if (category) {
      clauses.push("category = ?");
      params.push(category);
    }
    if (min_price != null) {
      clauses.push("price >= ?");
      params.push(Number(min_price));
    }
    if (max_price != null) {
      clauses.push("price <= ?");
      params.push(Number(max_price));
    }
    if (in_stock === "true") clauses.push("stock > 0");

    const rows = await all(
      `SELECT * FROM products WHERE ${clauses.join(" AND ")} ORDER BY name ASC`,
      params,
    );
    res.json({
      success: true,
      query: { q, category, min_price, max_price, in_stock },
      total: rows.length,
      data: rows,
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/products/aggregates  — category-level rollups (JOIN + GROUP BY)
app.get("/api/products/aggregates", async (req, res, next) => {
  try {
    const rows = await all(`
      SELECT
        p.category,
        COUNT(p.id)         AS product_count,
        ROUND(MIN(p.price),2) AS min_price,
        ROUND(MAX(p.price),2) AS max_price,
        ROUND(AVG(p.price),2) AS avg_price,
        SUM(p.stock)          AS total_stock,
        ROUND(AVG(r.rating),1) AS avg_rating,
        COUNT(r.id)            AS review_count
      FROM products p
      LEFT JOIN reviews r ON r.product_id = p.id
      GROUP BY p.category
      ORDER BY product_count DESC
    `);
    res.json({ success: true, data: rows });
  } catch (err) {
    next(err);
  }
});

// GET /api/products/top-rated  — products with highest average rating
app.get("/api/products/top-rated", async (req, res, next) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 5, 20);
    const rows = await all(
      `
      SELECT
        p.id, p.name, p.category, p.price, p.stock,
        ROUND(AVG(r.rating),1) AS avg_rating,
        COUNT(r.id)            AS review_count
      FROM products p
      JOIN reviews r ON r.product_id = p.id
      GROUP BY p.id
      ORDER BY avg_rating DESC, review_count DESC
      LIMIT ?
    `,
      [limit],
    );
    res.json({ success: true, data: rows });
  } catch (err) {
    next(err);
  }
});

// GET /api/products/low-stock  — items where stock ≤ threshold (default 20)
app.get(
  "/api/products/low-stock",
  authenticate,
  requireRole("editor", "admin"),
  async (req, res, next) => {
    try {
      const threshold = parseInt(req.query.threshold) || 20;
      const rows = await all(
        "SELECT * FROM products WHERE stock <= ? ORDER BY stock ASC",
        [threshold],
      );
      res.json({ success: true, threshold, total: rows.length, data: rows });
    } catch (err) {
      next(err);
    }
  },
);

// ── ROUTES: Stock management ────────────────────────────────

// POST /api/products/:id/restock  — increment stock by qty
app.post(
  "/api/products/:id/restock",
  authenticate,
  requireRole("editor", "admin"),
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      const qty = parseInt(req.body.qty);
      if (!Number.isInteger(qty) || qty <= 0)
        return res
          .status(400)
          .json({
            success: false,
            error: {
              code: "VALIDATION_ERROR",
              message: "'qty' must be a positive integer",
            },
          });

      const existing = await get("SELECT * FROM products WHERE id = ?", [id]);
      if (!existing)
        return res
          .status(404)
          .json({
            success: false,
            error: { code: "NOT_FOUND", message: "Product not found" },
          });

      await run(
        "UPDATE products SET stock = stock + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [qty, id],
      );
      const updated = await get("SELECT * FROM products WHERE id = ?", [id]);
      res.json({
        success: true,
        message: `Restocked +${qty} units`,
        data: updated,
      });
    } catch (err) {
      next(err);
    }
  },
);

// POST /api/products/:id/destock  — decrement stock by qty (cannot go below 0)
app.post(
  "/api/products/:id/destock",
  authenticate,
  requireRole("editor", "admin"),
  async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      const qty = parseInt(req.body.qty);
      if (!Number.isInteger(qty) || qty <= 0)
        return res
          .status(400)
          .json({
            success: false,
            error: {
              code: "VALIDATION_ERROR",
              message: "'qty' must be a positive integer",
            },
          });

      const existing = await get("SELECT * FROM products WHERE id = ?", [id]);
      if (!existing)
        return res
          .status(404)
          .json({
            success: false,
            error: { code: "NOT_FOUND", message: "Product not found" },
          });
      if (existing.stock < qty)
        return res
          .status(409)
          .json({
            success: false,
            error: {
              code: "INSUFFICIENT_STOCK",
              message: `Only ${existing.stock} units in stock`,
            },
          });

      await run(
        "UPDATE products SET stock = stock - ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [qty, id],
      );
      const updated = await get("SELECT * FROM products WHERE id = ?", [id]);
      res.json({
        success: true,
        message: `Removed ${qty} units from stock`,
        data: updated,
      });
    } catch (err) {
      next(err);
    }
  },
);

// ── ROUTES: Bulk operations ─────────────────────────────────

// POST /api/products/bulk-create  (admin) — insert multiple products in one transaction
app.post(
  "/api/products/bulk-create",
  authenticate,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const items = req.body.products;
      if (!Array.isArray(items) || items.length === 0)
        return res
          .status(400)
          .json({
            success: false,
            error: {
              code: "VALIDATION_ERROR",
              message: "'products' must be a non-empty array",
            },
          });
      if (items.length > 50)
        return res
          .status(400)
          .json({
            success: false,
            error: {
              code: "VALIDATION_ERROR",
              message: "Maximum 50 products per bulk insert",
            },
          });

      const allErrors = [];
      items.forEach((item, i) => {
        const e = validateProduct(item);
        if (e.length) allErrors.push(`Item ${i}: ${e.join("; ")}`);
      });
      if (allErrors.length)
        return res
          .status(400)
          .json({
            success: false,
            error: { code: "VALIDATION_ERROR", message: allErrors.join(" | ") },
          });

      // Use a transaction so either all succeed or none do
      await run("BEGIN TRANSACTION");
      const insertedIds = [];
      try {
        for (const {
          name,
          category,
          price,
          stock = 0,
          description = "",
        } of items) {
          const r = await run(
            "INSERT INTO products (name, category, price, stock, description) VALUES (?,?,?,?,?)",
            [
              name.trim(),
              category.trim().toLowerCase(),
              price,
              stock,
              String(description).trim(),
            ],
          );
          insertedIds.push(r.lastID);
        }
        await run("COMMIT");
      } catch (txErr) {
        await run("ROLLBACK");
        throw txErr;
      }

      const created = await all(
        `SELECT * FROM products WHERE id IN (${insertedIds.map(() => "?").join(",")})`,
        insertedIds,
      );
      res
        .status(201)
        .json({ success: true, inserted: created.length, data: created });
    } catch (err) {
      next(err);
    }
  },
);

// DELETE /api/products/bulk-delete  (admin) — delete many products by IDs
app.delete(
  "/api/products/bulk-delete",
  authenticate,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const ids = req.body.ids;
      if (!Array.isArray(ids) || ids.length === 0)
        return res
          .status(400)
          .json({
            success: false,
            error: {
              code: "VALIDATION_ERROR",
              message: "'ids' must be a non-empty array",
            },
          });

      const placeholders = ids.map(() => "?").join(",");
      const { n } = await get(
        `SELECT COUNT(*) as n FROM products WHERE id IN (${placeholders})`,
        ids,
      );
      await run(`DELETE FROM products WHERE id IN (${placeholders})`, ids);
      res.json({ success: true, deleted: n });
    } catch (err) {
      next(err);
    }
  },
);

// ── Error handler ───────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error("[ERROR]", err.message);
  res
    .status(500)
    .json({
      success: false,
      error: { code: "INTERNAL_SERVER_ERROR", message: "Something went wrong" },
    });
});

// ── Start ───────────────────────────────────────────────────
const server = app.listen(PORT, () =>
  console.log(
    `\n  REST API Lab running → http://localhost:${PORT}\n  Concept notes     → http://localhost:${PORT}/concept.html\n`,
  ),
);

const closeDatabase = () =>
  new Promise((res, rej) => db.close((e) => (e ? rej(e) : res())));
module.exports = { app, db, closeDatabase };
