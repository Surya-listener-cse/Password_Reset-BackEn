var express = require("express");
var router = express.Router();
const mongoose = require("mongoose");
const userController = require("../controllers/userController");
const auth = require("../middlewares/auth");

require("dotenv").config();

const dbUrl =  "mongodb+srv://suryadsp20:NrQdcm6HsY07BT4o@backend.17l9p3e.mongodb.net/?retryWrites=true&w=majority&appName=backend"

mongoose.connect(process.env.dbUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    
  })
  .then(()=>console.log('Connected to db'))
  .catch((err)=> console.log("DB connection error",err));
  


router.get("/", function(_, res) {
    res.render("index", { title: "Express" });
});

router.post("/auth/signup", userController.signup);
router.post("/auth/activate", userController.activate);
router.post("/auth/signin", userController.signin);
router.post("/auth/access", userController.access);
router.post("/auth/forgot", userController.forgot);
router.post("/auth/reset", auth, userController.reset);
router.get("/auth/user", auth, userController.info);
router.patch("/auth/update_user", auth, userController.update);
router.get("/auth/signout", userController.signout);

module.exports = router;