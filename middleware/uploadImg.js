const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const cloudStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "image post",
    format: async (req, file) => {
      const originalExt = file.originalname.split(".").pop();
      return originalExt;
    },
    public_id: (req, file) => file.name,
  },
});

const uploadImg = multer({ storage: cloudStorage });

module.exports = uploadImg;