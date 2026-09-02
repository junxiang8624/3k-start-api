const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const router = express.Router();
const SALT_ROUNDS = 10;

// 登入限制:同一個 IP,15 分鐘內最多嘗試 5 次
// 用意:防止有人寫腳本狂猜密碼(暴力破解)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 分鐘
  max: 5,
  message: { message: "嘗試登入次數過多，請 15 分鐘後再試" },
  standardHeaders: true,
  legacyHeaders: false,
});

// 註冊限制:同一個 IP,1 小時內最多註冊 3 次
// 用意:防止短時間內被灌大量假帳號
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 小時
  max: 3,
  message: { message: "註冊次數過多，請 1 小時後再試" },
  standardHeaders: true,
  legacyHeaders: false,
});

function createAuthRouter(db) {
  const usersCollection = db.collection("users");

  // 註冊
  router.post("/register", registerLimiter, async (req, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(400).json({ message: "帳號密碼不可為空" });
      }

      const existingUser = await usersCollection.findOne({ username });
      if (existingUser) {
        return res.status(409).json({ message: "帳號已存在" });
      }

      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

      await usersCollection.insertOne({
        username,
        password: hashedPassword,
        createdAt: new Date(),
      });

      res.status(201).json({ message: "註冊成功" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "伺服器錯誤" });
    }
  });

  // 登入
  router.post("/login", loginLimiter, async (req, res) => {
    try {
      const { username, password } = req.body;

      const user = await usersCollection.findOne({ username });

      // 帳號不存在 或 密碼錯誤 都回同一句話，避免被猜帳號
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: "帳號或密碼錯誤" });
      }

      const token = jwt.sign(
        { userId: user._id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );

      res.json({ message: "登入成功", token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "伺服器錯誤" });
    }
  });

  // 驗證目前的 token 是否有效，並回傳使用者資訊
  // 前端在頁面載入時呼叫這支，判斷要顯示「登入/註冊」還是「歡迎 xxx」
  router.get("/me", async (req, res) => {
    try {
      const authHeader = req.headers["authorization"]; // 格式："Bearer xxxxx"
      const token = authHeader && authHeader.split(" ")[1];

      if (!token) {
        return res.status(401).json({ message: "未登入" });
      }

      // 驗證 token 簽名是否正確、是否過期
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      res.json({ username: decoded.username });
    } catch (err) {
      // token 過期或被竄改，jwt.verify 會丟出錯誤
      return res.status(401).json({ message: "登入已過期，請重新登入" });
    }
  });

  return router;
}

module.exports = createAuthRouter;
