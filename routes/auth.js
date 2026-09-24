const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const SALT_ROUNDS = 10;

// 登入限制:同一個 IP,15 分鐘內最多嘗試 5 次
// 用意:防止有人寫腳本狂猜密碼(暴力破解)
// 注意:要搭配 index.js 裡的 app.set("trust proxy", 1),在 Render 上才抓得到真實 IP
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

// [新增] 帳號規則:3~20 字,只能用英文字母、數字、底線
const USERNAME_PATTERN = /^[A-Za-z0-9_]{3,20}$/;

// [新增] 檢查帳號密碼是不是字串
// 用意:如果有人送 {"username": {"$ne": null}} 這種物件,會被當成 MongoDB 查詢條件(NoSQL injection)
function isValidInput(username, password) {
  return typeof username === "string" && typeof password === "string";
}

function createAuthRouter(db) {
  // [修改] router 移進函式裡,每次呼叫都拿到一個乾淨的新 router
  const router = express.Router();
  const usersCollection = db.collection("users");

  // [新增] 讓資料庫保證帳號不重複
  // 只靠「先查有沒有,再新增」的話,兩個人同時註冊同一個帳號時還是可能兩筆都寫進去
  usersCollection
    .createIndex({ username: 1 }, { unique: true })
    .catch((err) => console.error("建立 username 索引失敗:", err));

  // 註冊
  router.post("/register", registerLimiter, async (req, res) => {
    try {
      const { username, password } = req.body || {};

      if (!isValidInput(username, password) || !username || !password) {
        return res.status(400).json({ message: "帳號密碼不可為空" });
      }

      // [新增] 帳號格式
      if (!USERNAME_PATTERN.test(username)) {
        return res.status(400).json({ message: "帳號須為 3~20 字的英文字母、數字或底線" });
      }

      // [新增] 密碼長度;bcrypt 只看前 72 bytes,超過的部分會被忽略,所以設上限
      const passwordBytes = Buffer.byteLength(password, "utf8");
      if (password.length < 8 || passwordBytes > 72) {
        return res.status(400).json({ message: "密碼長度須為 8 字以上,且不可過長" });
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
      // [新增] 11000 是 MongoDB「違反唯一索引」的錯誤代碼,代表帳號剛好同時被別人註冊走
      if (err.code === 11000) {
        return res.status(409).json({ message: "帳號已存在" });
      }
      console.error(err);
      res.status(500).json({ message: "伺服器錯誤" });
    }
  });

  // 登入
  router.post("/login", loginLimiter, async (req, res) => {
    try {
      const { username, password } = req.body || {};

      // [新增] 型別檢查,擋掉物件型態的查詢條件
      if (!isValidInput(username, password)) {
        return res.status(400).json({ message: "帳號或密碼格式錯誤" });
      }

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
  router.get("/me", (req, res) => {
    const authHeader = req.headers["authorization"]; // 格式："Bearer xxxxx"
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ message: "未登入" });
    }

    try {
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
