var functions = require("firebase-functions");
var express = require("express");
var app = express();
const cloudinary = require("cloudinary");
const base64url = require("base64url");
const { createHmac } = require("crypto");

cloudinary.config({
  cloud_name: "albaongaro",
  api_key: functions.config().cloudinary.key,
  api_secret: functions.config().cloudinary.secret,
});

const verifyPostRequestSignature = ({
  secret,
  signatures,
  timestamp,
  path,
  body,
}) => {
  // Decode the secret as a "base64url" and convert it into bytes
  const digest = base64url.toBuffer(secret);

  // Create the required payload for generating a signature
  const payload = `v1:${timestamp}:${path}:${body}`;

  // Generate a signature as a SHA-256 hash
  const signature = createHmac("sha256", digest).update(payload).digest("hex");

  // If the "signatures" list contains the generated signature, the request is valid
  if (signatures.split(",").includes(signature)) {
    return true;
  }

  // Otherwise, the request not valid
  return false;
};

const verifyTimestamp = ({ receivedAt, sentAt, leniencyInSeconds }) => {
  if (sentAt - receivedAt > leniencyInSeconds) {
    // The timestamp is in the future
    return false;
  }

  if (receivedAt - sentAt > leniencyInSeconds) {
    // The timestamp has expired
    return false;
  }

  // The timestamp is valid
  return true;
};

app.use(
  express.json({
    verify: (request, response, buffer) => {
      // Verify the timestamp
      const currentTime = new Date().getTime() / 1000;
      const timestamp = Number(request.header("X-Canva-Timestamp"));
      const leniencyInSeconds = 300;

      const validTimestamp = verifyTimestamp({
        receivedAt: currentTime,
        sentAt: timestamp,
        leniencyInSeconds,
      });

      // Verify the request signature
      const secret = functions.config().canva.client_secret;
      const signatures = request.header("X-Canva-Signatures");
      const path = request.path;
      const body = buffer.toString();

      const validSignature = verifyPostRequestSignature({
        secret,
        signatures,
        path,
        body,
        timestamp,
      });

      // Respond with a 401 status code if the request is not valid
      if (!validTimestamp || !validSignature) {
        response.status(401).send("Invalid request");
      }
    },
  })
);

app.post("/publish/resources/upload", async (request, response) => {
  for (let asset of request.body.assets) {
    cloudinary.v2.uploader.upload(
      asset.url,
      {
        folder: "thumbnails",
        public_id: asset.name.replace(/\..{3,}$/g, ""),
      },
      () => {
        response.send({
          type: "SUCCESS",
        });
      }
    );
  }
});

exports.canva = functions.https.onRequest(app);
