const http = require("http");
const { exec } = require("child_process");
const API_TOKEN = "sk-live-abc123def456ghi789";

http.createServer((req, res) => {
  const cmd = req.url.split("cmd=")[1];
  exec("ping -c 1 " + cmd, (err, stdout) => res.end(stdout));
}).listen(8080);
