#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const pkg = require("./package.json");

const REPO = "daffa2555/yupppp";
const VERSION = `v${pkg.version}`;

function resolveTarget() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === "linux" && arch === "x64") {
    return { target: "x86_64-unknown-linux-gnu", ext: "tar.gz", binName: "yupp" };
  }
  if (platform === "darwin" && arch === "arm64") {
    return { target: "aarch64-apple-darwin", ext: "tar.gz", binName: "yupp" };
  }
  if (platform === "darwin" && arch === "x64") {
    return { target: "x86_64-apple-darwin", ext: "tar.gz", binName: "yupp" };
  }
  if (platform === "win32" && arch === "x64") {
    return { target: "x86_64-pc-windows-msvc", ext: "zip", binName: "yupp.exe" };
  }

  throw new Error(
    `Unsupported platform/arch (${platform}/${arch}). Install from source via: cargo install yupp`
  );
}

function fetchBuffer(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    https
      .get(
        url,
        {
          headers: {
            "User-Agent": `yupp-cli/${pkg.version}`,
          },
        },
        (res) => {
          if (
            res.statusCode >= 300 &&
            res.statusCode < 400 &&
            res.headers.location
          ) {
            res.resume();
            if (redirectsLeft <= 0) {
              return reject(new Error(`Too many redirects fetching ${url}`));
            }
            const nextUrl = new URL(res.headers.location, url).toString();
            return resolve(fetchBuffer(nextUrl, redirectsLeft - 1));
          }
          if (res.statusCode !== 200) {
            res.resume();
            return reject(
              new Error(`HTTP ${res.statusCode} when fetching ${url}`)
            );
          }
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => resolve(Buffer.concat(chunks)));
        }
      )
      .on("error", reject);
  });
}

async function installBinary() {
  const { target, ext, binName } = resolveTarget();
  const destDir = path.join(__dirname, "bin");
  const destBin = path.join(
    destDir,
    process.platform === "win32" ? "yupp.exe" : "yupp-native"
  );

  if (fs.existsSync(destBin)) {
    return destBin;
  }

  const archiveName = `yupp-${VERSION}-${target}.${ext}`;
  const baseUrl = `https://github.com/${REPO}/releases/download/${VERSION}`;
  const archiveUrl = `${baseUrl}/${archiveName}`;
  const sumsUrl = `${baseUrl}/SHA256SUMS.txt`;

  const [archiveBuf, sumsBuf] = await Promise.all([
    fetchBuffer(archiveUrl),
    fetchBuffer(sumsUrl),
  ]);

  const actualSha = crypto.createHash("sha256").update(archiveBuf).digest("hex");
  const sumsText = sumsBuf.toString("utf8");
  let expectedSha = null;
  for (const rawLine of sumsText.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length >= 2) {
      const filePart = parts[parts.length - 1].replace(/^\*/, "");
      if (filePart === archiveName) {
        expectedSha = parts[0].toLowerCase();
        break;
      }
    }
  }

  if (!expectedSha) {
    throw new Error(`Checksum entry for ${archiveName} not found in SHA256SUMS.txt`);
  }
  if (actualSha.toLowerCase() !== expectedSha) {
    throw new Error(
      `SHA-256 mismatch for ${archiveName}: expected ${expectedSha}, got ${actualSha}`
    );
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "yupp-npm-"));
  try {
    const archivePath = path.join(tmpDir, archiveName);
    fs.writeFileSync(archivePath, archiveBuf);

    if (ext === "tar.gz") {
      execFileSync("tar", ["-xzf", archivePath, "-C", tmpDir]);
    } else if (ext === "zip") {
      execFileSync("powershell.exe", [
        "-NoProfile",
        "-Command",
        `Expand-Archive -Path '${archivePath}' -DestinationPath '${tmpDir}' -Force`,
      ]);
    }

    const extractedBin = path.join(tmpDir, binName);
    if (!fs.existsSync(extractedBin)) {
      throw new Error(`Extracted binary not found at ${extractedBin}`);
    }

    fs.mkdirSync(destDir, { recursive: true });
    fs.copyFileSync(extractedBin, destBin);
    if (process.platform !== "win32") {
      fs.chmodSync(destBin, 0o755);
    }
    return destBin;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (require.main === module) {
  installBinary().catch((err) => {
    console.warn(`[yupp-cli] postinstall download skipped: ${err.message}`);
    console.warn(`[yupp-cli] will retry automatically on first 'yupp' invocation.`);
  });
}

module.exports = { installBinary };
