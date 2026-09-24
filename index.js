/**
 * 「隊伍介紹」武將圖片上傳功能 — Express 版
 * 對應原本 Python 的 team_images.py,路由、邏輯一一對應
 *
 * 資料清單存在 MongoDB Atlas(不用本地檔案),
 * Render 容器重啟/重新部署,資料也不會消失。
 */

require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { MongoClient } = require("mongodb");
const createAuthRouter = require("./routes/auth");

// [新增] 啟動前先檢查必要的環境變數,缺了就直接停止,比執行到一半才出錯好除錯
const REQUIRED_ENV = ["MONGODB_URI", "JWT_SECRET"];
const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]);
if (missingEnv.length > 0) {
  console.error(`缺少必要的環境變數: ${missingEnv.join(", ")}`);
  process.exit(1);
}

const app = express();

// [新增] Render 前面有一層代理伺服器,要信任它轉過來的真實 IP,
// 不然所有使用者看起來都是同一個 IP,登入限流會變成全站共用 5 次
app.set("trust proxy", 1);

// 允許前端跨網域讀取(CORS)— 限制只有這些網域能呼叫這支 API
const allowedOrigins = [
  "http://localhost:5500",           // 本地測試用（Live Server 的網址,依你實際的 port 調整）
  "http://127.0.0.1:5500",           // Live Server 有時會用這個網址開,兩個都要加
  "http://localhost:5173",           // Vue 專案開發用（npm run dev）
  "http://localhost:4173",           // Vue 專案預覽用（npm run preview）
  "https://3k-start.netlify.app",    // 正式上線的 Netlify 網址
];

app.use(cors({
  origin: allowedOrigins,
}));
app.use(express.json({ limit: "10kb" })); // [修改] JSON 內容只有帳號密碼,限制大小避免被塞超大資料

// 設定 Cloudinary(值來自 Render 環境變數,不寫死在程式碼裡)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// multer:圖片先存進記憶體(對應 Python 的 await file.read()),再轉手給 Cloudinary
// [修改] 限制單檔 5MB,且只接受圖片,避免有人上傳超大檔案把記憶體吃光
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("只能上傳圖片檔"));
    }
  },
});

// 連線 MongoDB Atlas(連線字串存在 Render 環境變數 MONGODB_URI)
const mongoClient = new MongoClient(process.env.MONGODB_URI);
let teamImagesCollection;

async function connectMongo() {
  await mongoClient.connect();
  const db = mongoClient.db("threekingdoms"); // 資料庫名稱,跟連線字串裡設的一致
  teamImagesCollection = db.collection("team_images"); // 相當於原本 json 檔裡的那份清單
  console.log("MongoDB 連線成功");
  return db;
}

// [新增] 安全的字串比對:一般的 !== 比對時間會隨「前面有幾個字對了」而不同,
// 理論上可以被拿來一個字一個字猜密碼,timingSafeEqual 則永遠花一樣的時間
function safeEqual(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// 檢查上傳/刪除密碼;沒設定 TEAM_IMAGES_PASSWORD 環境變數時,視為不啟用密碼保護
function checkPassword(req, res) {
  const correctPassword = process.env.TEAM_IMAGES_PASSWORD;
  if (!correctPassword) return true; // 沒設定密碼,不做檢查(方便本地測試,正式上線建議一定要設)

  const provided = req.headers["x-upload-password"];
  if (typeof provided !== "string" || !safeEqual(provided, correctPassword)) {
    res.status(401).json({ detail: "密碼錯誤" });
    return false;
  }
  return true;
}

// MongoDB 文件裡的內部 _id(ObjectId)前端不需要,拿掉它
function serialize(doc) {
  if (!doc) return doc;
  const { _id, ...rest } = doc;
  return rest;
}

app.get("/", (req, res) => {
  res.json({ status: "success", message: "隊伍介紹圖片 API 已連線" });
});

// 10. 上傳一張武將圖片(表單需帶 name 欄位 + file 檔案,還需帶密碼 header)
app.post("/api/team-images/upload", upload.single("file"), async (req, res) => {
  if (!checkPassword(req, res)) return;

  const { name } = req.body;
  const file = req.file;

  // [修改] 多檢查 name 必須是字串,且長度合理
  if (typeof name !== "string" || !name.trim() || name.length > 50 || !file) {
    return res.status(422).json({ detail: "缺少 name 或 file,或 name 格式不正確" });
  }

  if (!cloudinary.config().cloud_name) {
    return res.status(500).json({ detail: "尚未設定 Cloudinary,請先在 Render 加上環境變數" });
  }

  try {
    // 用 upload_stream 把記憶體中的 buffer 傳給 Cloudinary(對應 Python 的 cloudinary.uploader.upload(contents, ...))
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: "3k-web/team-images" },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );
      stream.end(file.buffer);
    });

    const newEntry = {
      id: result.public_id, // 用 Cloudinary 的 public_id 當唯一識別碼,方便之後刪除
      name: name.trim(),
      imageUrl: result.secure_url,
    };

    await teamImagesCollection.insertOne(newEntry);

    res.json(serialize(newEntry));
  } catch (err) {
    console.error(err);
    res.status(500).json({ detail: `上傳失敗: ${err.message}` });
  }
});

// 11. 取得所有已上傳的武將圖片(前端載入頁面時用這支抓資料)
// [修改] 加上 try/catch,資料庫出錯時回 500,而不是讓請求卡住
app.get("/api/team-images", async (req, res) => {
  try {
    const images = await teamImagesCollection.find({}).toArray();
    res.json(images.map(serialize));
  } catch (err) {
    console.error(err);
    res.status(500).json({ detail: "讀取圖片清單失敗" });
  }
});

// 12. 刪除一張武將圖片(依 id,也就是 Cloudinary 的 public_id,還需帶密碼 header)
// 注意:public_id 裡通常帶有斜線(例如 3k-web/team-images/xxx),所以用萬用路由 (*) 接住整段
app.delete("/api/team-images/*", async (req, res) => {
  if (!checkPassword(req, res)) return;

  const imageId = req.params[0]; // 對應 Python 的 {image_id:path}

  // [修改] 整段包進 try/catch,資料庫出錯也能正常回應
  try {
    const target = await teamImagesCollection.findOne({ id: imageId });
    if (!target) {
      return res.status(404).json({ detail: "找不到這筆圖片資料" });
    }

    try {
      await cloudinary.uploader.destroy(imageId);
    } catch (err) {
      return res.status(500).json({ detail: `從 Cloudinary 刪除失敗: ${err.message}` });
    }

    await teamImagesCollection.deleteOne({ id: imageId });

    res.json({ status: "success", message: `已刪除 ${target.name} 的圖片` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ detail: "刪除失敗" });
  }
});

// [新增] 統一處理錯誤(例如檔案太大、不是圖片、JSON 格式錯誤)
// Express 認得「4 個參數」的函式是錯誤處理器,所以 next 就算沒用到也要寫
function errorHandler(err, req, res, next) {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({ detail: "檔案太大,上限 5MB" });
    }
    return res.status(400).json({ detail: `上傳錯誤: ${err.message}` });
  }
  if (err.message === "只能上傳圖片檔") {
    return res.status(400).json({ detail: err.message });
  }
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ message: "JSON 格式錯誤" });
  }
  console.error(err);
  res.status(500).json({ detail: "伺服器錯誤" });
}

const PORT = process.env.PORT || 3000;

// [修改] 連上資料庫後才掛 /auth 路由,再掛錯誤處理器(錯誤處理器必須放在所有路由之後)
connectMongo()
  .then((db) => {
    app.use("/auth", createAuthRouter(db));
    app.use(errorHandler);

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("MongoDB 連線失敗:", err);
    process.exit(1);
  });
