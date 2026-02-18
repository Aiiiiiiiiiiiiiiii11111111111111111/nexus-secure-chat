const WebSocket = require("ws");
const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const db = require("./database");
const cors = require("cors");
const { encryptAES, decryptAES, generateECDH } = require("./crypto");

const app = express();
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT || 10000;

const SECRET = "JWT_SECRET";

const wss = new WebSocket.Server({ port: PORT });
let online = {};

wss.on("connection", ws=>{
  // generate server ECDH key pair for this connection
  ws.ecdh = generateECDH();

  ws.on("message", msg=>{
    try{
      const data = JSON.parse(msg.toString());
      // handle login/register
      if(data.type==="login"){ online[data.username]=ws; }
      if(data.type==="register"){ /* save to db */ }
      if(data.type==="private_msg"){
        const target = online[data.to];
        if(target) target.send(JSON.stringify({
          type:"private",from:data.from,msg:data.msg
        }));
      }
      if(data.type==="file"){
        const target = online[data.to];
        if(target) target.send(JSON.stringify(data));
      }
    }catch(e){ console.log(e); }
  });

  ws.on("close", ()=>{
    for(const u in online){ if(online[u]===ws) delete online[u]; }
  });
});

console.log("Secure Nexus Server running...");
