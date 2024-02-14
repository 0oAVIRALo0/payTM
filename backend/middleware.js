const jwt = require("jsonwebtoken");
const JWT_SECRET = require("./config");

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(403).json({
      error: "Authorization header not found",
    });
  }

  const authHeaderWithoutBearer = authHeader.split("Bearer ")[1];

  try {
    const decoded = jwt.verify(authHeaderWithoutBearer, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(403).json({
      error: "Invalid token",
    });
  }
};

module.exports = {
  authMiddleware,
};
