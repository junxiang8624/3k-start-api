/**
 * 「隊伍介紹」武將圖片上傳功能 — Express 版
 * 對應原本 Python 的 team_images.py,路由、邏輯一一對應
 *
 * 資料清單存在 MongoDB Atlas(不用本地檔案),
 * Render 容器重啟/重新部署,資料也不會消失。
 */

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { MongoClient } = require("mongodb");
const createAuthRouter = require("./routes/auth");

const app = express();

// 允許前端跨網域讀取(CORS)— 限制只有這些網域能呼叫這支 API
const allowedOrigins = [
  "http://localhost:5500",           // 本地測試用（Live Server 的網址,依你實際的 port 調整）
  "http://127.0.0.1:5500",           // Live Server 有時會用這個網址開,兩個都要加
  "https://3k-start.netlify.app",    // 正式上線的 Netlify 網址
];

app.use(cors({
  origin: allowedOrigins,
}));
app.use(express.json());

// 設定 Cloudinary(值來自 Render 環境變數,不寫死在程式碼裡)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// multer:圖片先存進記憶體(對應 Python 的 await file.read()),再轉手給 Cloudinary
const upload = multer({ storage: multer.memoryStorage() });

// 連線 MongoDB Atlas(連線字串存在 Render 環境變數 MONGODB_URI)
const mongoClient = new MongoClient(process.env.MONGODB_URI);
let teamImagesCollection;

async function connectMongo() {
  await mongoClient.connect();
  const db = mongoClient.db("threekingdoms"); // 資料庫名稱,跟連線字串裡設的一致
  teamImagesCollection = db.collection("team_images"); // 相當於原本 json 檔裡的那份清單

  // 掛上帳號登入/註冊路由
  app.use("/auth", createAuthRouter(db));

  console.log("MongoDB 連線成功");
}

// 檢查上傳/刪除密碼;沒設定 TEAM_IMAGES_PASSWORD 環境變數時,視為不啟用密碼保護
function checkPassword(req, res) {
  const correctPassword = process.env.TEAM_IMAGES_PASSWORD;
  if (!correctPassword) return true; // 沒設定密碼,不做檢查(方便本地測試,正式上線建議一定要設)

  const provided = req.headers["x-upload-password"];
  if (provided !== correctPassword) {
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

  if (!name || !file) {
    return res.status(422).json({ detail: "缺少 name 或 file" });
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
      name,
      imageUrl: result.secure_url,
    };

    await teamImagesCollection.insertOne(newEntry);

    res.json(serialize(newEntry));
  } catch (err) {
    res.status(500).json({ detail: `上傳失敗: ${err.message}` });
  }
});

// 11. 取得所有已上傳的武將圖片(前端載入頁面時用這支抓資料)
app.get("/api/team-images", async (req, res) => {
  const images = await teamImagesCollection.find({}).toArray();
  res.json(images.map(serialize));
});

// 12. 刪除一張武將圖片(依 id,也就是 Cloudinary 的 public_id,還需帶密碼 header)
// 注意:public_id 裡通常帶有斜線(例如 3k-web/team-images/xxx),所以用萬用路由 (*) 接住整段
app.delete("/api/team-images/*", async (req, res) => {
  if (!checkPassword(req, res)) return;

  const imageId = req.params[0]; // 對應 Python 的 {image_id:path}

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
});

const PORT = process.env.PORT || 3000;

connectMongo()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("MongoDB 連線失敗:", err);
    process.exit(1);
  });
