import express from "express";
import { MongoClient } from "mongodb";
import bcrypt from "bcrypt";
import cors from "cors";
import jwt from "jsonwebtoken";
import * as dotenv from "dotenv";
import { ObjectId } from "mongodb";
import nodemailer from "nodemailer";
dotenv.config();
const app = express();

const PORT = process.env.PORT;

const MONGO_URL = process.env.MONGO_URL;

const client = new MongoClient(MONGO_URL); // dial
// Top level await
await client.connect(); // call
console.log("Mongo is connected !!!  ");
app.use(cors());

// app.use(express.urlencoded({ extended: false }));
app.get("/", function (request, response) {
  response.send("🙋‍♂️, 🌏 🎊✨🤩");
});

async function genrateHashedPassword(password) {
  const NO_OF_ROUNDS = 10;
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
  const HashedPassword = await bcrypt.hash(password, salt);
  return HashedPassword;
}
app.post("/users/signup", express.json(), async function (request, response) {
  const { name, email, password } = request.body;
  const userfromdb = await client
    .db("b42wd2")
    .collection("users")
    .findOne({ email: email });

  if (userfromdb) {
    response.json({ status: "user already exists" });
  } else {
    const HashedPassword = await genrateHashedPassword(password);
    const result = await client.db("b42wd2").collection("users").insertOne({
      name: name,
      email: email,
      password: HashedPassword,
    });
    response.json({ status: "succesfully signuP" });
  }
});

app.post(
  "/users/forgot-password",
  express.json(),
  async function (request, response) {
    const { email } = request.body;
    try {
      const userfromdb = await client
        .db("b42wd2")
        .collection("users")
        .findOne({ email: email });

      if (!userfromdb) {
        response.json({ status: "user already exists" });
      }
      const secret = process.env.SECURITY_KEY + userfromdb.password;
      const token = jwt.sign(
        { email: userfromdb.email, id: userfromdb._id },
        secret,
        { expiresIn: "5m" }
      );
      const link = `http://localhost:5173/reset-password?id=${userfromdb._id}&token=${token}`;

      // create reusable transporter object using the default SMTP transport
      let transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: "Mohanvijay8344@gmail.com",
          pass: "biknetgulezybmjc",
        },
      });

      // setup email data with unicode symbols
      let mailOptions = {
        from: "Mohanvijay8344@gmail.com", // sender address
        to: userfromdb.email, // list of receivers
        subject: "forgot password reset flow using nodejs and nodemailer", // Subject line
        // plain text body
        html: `<a href=${link}>click here</a>`,
      };

      // send mail with defined transport object
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          return console.log(error);
        }
        console.log("Message sent: %s", info.messageId);
        response.status(200).json();
      });

      // console.log(link);
    } catch (error) {}
  }
);

app.get("/user/reset-password/:id/:token", async function (request, response) {
  const { id, token } = request.params;
  console.log(request.params);
  const userfromdb = await client
    .db("b42wd2")
    .collection("users")
    .findOne({ _id: id });

  if (!userfromdb) {
    response.send({ message: "user not exists" });
  }
  const secret = process.env.SECURITY_KEY + userfromdb.password;
  try {
    const verify = jwt.verify(token, secret);
    response.render("index", { email: verify.email });
  } catch (error) {
    console.log(error);
    response.send({ message: "not verified" });
  }
});

app.post(
  "/user/reset-password/:id/:token",
  express.json(),
  async function (request, response) {
    const { id, token } = request.params;
    const { password } = request.body;
    const userfromdb = await client
      .db("b42wd2")
      .collection("users")
      .findOne({ _id: new ObjectId(id) });
    if (!userfromdb) {
      response.send({ message: "user not exists" });
    }
    const secret = process.env.SECURITY_KEY + userfromdb.password;
    try {
      const verify = jwt.verify(token, secret);
      const HashedPassword = await genrateHashedPassword(password);
      const result = await client
        .db("b42wd2")
        .collection("users")

        .updateOne(
          {
            password: userfromdb.password,
          },
          {
            $set: {
              password: HashedPassword,
            },
          }
        );
      response.send({ message: "password updated" });
      console.log(result);
    } catch (error) {
      console.log(error);
      response.send({ message: "not verified" });
    }
  }
);

app.listen(PORT, () => console.log(`The server started in: ${PORT} ✨✨`));
