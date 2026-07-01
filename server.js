const clone = require("clone");
const data = require("./db.json");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");

const isProductionEnv = process.env.NODE_ENV === "production";

const server = jsonServer.create();
const PORT = Number(process.env.PORT) || 3000;
const SECRET_KEY = process.env.JWT_SECRET || "123456789";
const TOKEN_EXPIRATION = process.env.JWT_EXPIRES_IN || "1m";

// For mocking the POST request, POST request won't make any changes to the DB in production environment
const router = jsonServer.router(
  isProductionEnv ? clone(data) : "database.json",
  {
    _isFake: isProductionEnv
  }
);

server.use(jsonServer.bodyParser);
server.use(jsonServer.defaults());

if (isProductionEnv) {
  server.use((req, res, next) => {
    if (req.path !== "/") router.db.setState(clone(data));
    next();
  });
}

// Create a token from a payload
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn: TOKEN_EXPIRATION });
}

// Verify the token
function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY);
}

// Check if the user exists in database
function isAuthenticated({ email, password }) {
  return router.db
    .get("users")
    .some((user) => user.email === email && user.password === password)
    .value();
}

server.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!isAuthenticated({ email, password })) {
    const status = 401;
    const message = "Incorrect username or password";
    res.status(status).json({ status, message });
    return;
  }
  const accessToken = createToken({ email });
  res.status(200).json({ accessToken });
});

server.post("/users", (req, res) => {
  const { email, password } = req.body;
  if (email && password) {
    res.status(200).json({ message: `User created: ${email}` });
  } else {
    res
      .status(400)
      .json({ message: `Create failed: Email and password required` });
  }
});

server.get("/product/:id", (req, res) => {
  const id = req.params.id;
  const product = router.db
    .get("products")
    .find((item) => item.Id === id)
    .value();

  if (product) {
    res.status(200).json({ Result: product });
  } else {
    res.status(400).json({ Result: "No Product found" });
  }
});
server.get("/products/search/:query", (req, res) => {
  const query = req.params.query;
  const filtered = router.db
    .get("products")
    .filter((product) => product.Category === query)
    .value();

  if (filtered.length > 0) {
    res.status(200).json({ Result: filtered });
  } else {
    res.status(200).json({ Result: "No products found" });
  }
});

// checkout
server.post("/checkout", (req, res) => {
  const order = req.body;
  let error = false;
  let errorMsg = {};
  // console.log(order);
  // check for required fields
  if (!order.orderDate) {
    error = true;
    errorMsg.orderDate = "No Order Date";
  }
  if (!order.fname) {
    error = true;
    errorMsg.fname = "No First Name";
  }
  if (!order.lname) {
    error = true;
    errorMsg.lname = "No Last Name";
  }
  if (!order.street || !order.city || !order.state || !order.zip) {
    error = true;
    errorMsg.address = "Missing or incomplete address";
  }
  if (!order.cardNumber) {
    error = true;
    errorMsg.cardNumber = "No card number";
  } else if (order.cardNumber !== "1234123412341234") {
    // check for valid number
    error = true;
    errorMsg.cardNumber = "Invalid Card Number";
  }
  if (!order.expiration) {
    error = true;
    errorMsg.expiration = "Missing card expiration";
  } else {
    const parts = order.expiration.split("/");
    const month = Number(parts[0]);
    const year = Number(parts[1]);

    if (parts.length === 2 && month >= 1 && month <= 12 && Number.isInteger(year)) {
      // Card is valid through the end of the expiration month.
      const expireDate = new Date(2000 + year, month, 0, 23, 59, 59, 999);
      const curDate = new Date();

      if (expireDate < curDate) {
        error = true;
        errorMsg.expiration = "Card expired";
      }
    } else {
      error = true;
      errorMsg.expiration = "Invalid expiration date";
    }
  }
  if (error) {
    res.status(400).json(errorMsg);
  } else {
    const orders = router.db.get("orders").value() || [];
    const lastOrder = orders.reduce(
      (maxOrderId, currentOrder) => Math.max(maxOrderId, Number(currentOrder.id) || 0),
      0
    );

    order.id = lastOrder + 1;
    router.db.get("orders").push(order).write();
    res.status(200).json({ orderId: order.id, message: "Order Placed" });
  }
});

server.use((req, res, next) => {
  if (req.method === "POST") {
    const { authorization } = req.headers;
    if (authorization) {
      const [scheme, token] = authorization.split(" ");
      if (scheme === "Bearer" && token) {
        try {
          req.claims = verifyToken(token);
          req.body.userId = req.claims.email;
        } catch (err) {
          const status = 401;
          return res.status(status).json({ status, message: err.message });
        }
      }
    }

    req.body.createdAt = Date.now();
  }

  // Continue to JSON Server router
  next();
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    const status = 401;
    const message = "Error in authorization format";
    res.status(status).json({ status, message });
    return;
  }

  try {
    verifyToken(req.headers.authorization.split(" ")[1]);
    next();
  } catch (err) {
    const status = 401;
    const message = err.message;
    res.status(status).json({ status, message });
  }
});

server.use(router);

server.listen(PORT, () => {
  console.log(`Run Auth API Server on port ${PORT}`);
});

module.exports = server;
