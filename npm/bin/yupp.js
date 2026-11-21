#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { installBinary } = require("../install.js");

const binPath = path.join(
  __dirname,
  process.platform === "win32" ? "yupp.exe" : "yupp-native"
);

function run(executable) {
  const res = spawnSync(executable, process.argv.slice(2), {
    stdio: "inherit",
  });
  if (res.error) {
    console.error(`yupp error: ${res.error.message}`);
    process.exit(2);
  }
  process.exit(res.status !== null ? res.status : 1);
}

if (fs.existsSync(binPath)) {
  run(binPath);
} else {
  installBinary()
    .then((downloadedPath) => run(downloadedPath))
    .catch((err) => {
      console.error(`yupp error: failed to install native binary: ${err.message}`);
      process.exit(2);
    });
}
