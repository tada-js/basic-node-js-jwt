require("dotenv").config();
const cookieParser = require("cookie-parser");
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
const secretText = process.env.SECREAT_TEXT;
const refreshSecretText = process.env.REFRESH_SECREAT_TEXT;

const posts = [
  {
    username: "멍청새",
    title: "Post 1",
  },
  {
    username: "삐딱새",
    title: "Post 2",
  },
];
let refreshTokens = [];

app.use(express.json());
app.use(cookieParser());

app.post("/login", (req, res) => {
  const username = req.body.username;
  const user = { name: username };

  // jwt를 사용해서 토큰 생성 payload + secretText
  const accessToken = jwt.sign(user, secretText, { expiresIn: "30s" });

  // jwt 사용해서 refreshToken 생성
  const refreshToken = jwt.sign(user, refreshSecretText, { expiresIn: "1d" });

  // 일반적으로 refreshToken는 DB에 저장
  refreshTokens.push(refreshToken);

  // refreshToken 쿠키에 넣기
  res.cookie("jwt", refreshToken, {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.json({ accessToken: accessToken });
});

app.get("/posts", authMiddleware, (req, res) => {
  res.json(posts);
});

function authMiddleware(req, res, next) {
  // 토큰을 request headers에서 가져오기
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  // 토큰이 있으니 유효한 토큰인지 확인
  jwt.verify(token, secretText, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.get("/refresh", (req, res) => {
  // cookie-parser로 cookies 가져오기
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(403);
  const refreshToken = cookies.jwt;
  // refreshToken이 DB에 있는 토큰인지 확인
  if (!refreshToken.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, refreshSecretText, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = jwt.sign({ name: user.name }, secretText, {
      expiresIn: "30s",
    });
    res.json({ accessToken });
  });
});

const port = 4000;
app.listen(port, () => {
  console.log(`port ${port}`);
});
