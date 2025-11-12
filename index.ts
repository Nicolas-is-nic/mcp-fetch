#!/usr/bin/env node

import dns from "node:dns";
import { promises as fs } from "node:fs";
import net from "node:net";
import path from "node:path";
import type { Readable } from "node:stream";
import { URL } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Readability } from "@mozilla/readability";
import { JSDOM } from "jsdom";
import type { RequestInit } from "node-fetch";
import fetch, { type Response as FetchResponse } from "node-fetch";
import robotsParser from "robots-parser";
import sharp from "sharp";
import TurndownService from "turndown";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";

interface Image {
  src: string;
  alt: string;
  data?: Buffer;
  filename?: string;
}

interface ExtractedContent {
  markdown: string;
  images: Image[];
  title?: string;
}

interface ImageResource {
  uri: string;
  name: string;
  description: string;
  mimeType: string;
  filePath: string;
}

// Global resource registry for images
const imageResources = new Map<string, ImageResource>();

// Server instance to send notifications
let serverInstance: Server;
let serverConnected = false;

// --------------------
// Security hardening
// --------------------
// Defaults (can be overridden by env vars)
const FETCH_TIMEOUT_MS = Number(process.env.MCP_FETCH_TIMEOUT_MS || 12000);
const MAX_REDIRECTS = Number(process.env.MCP_FETCH_MAX_REDIRECTS || 3);
const MAX_HTML_BYTES = Number(
  process.env.MCP_FETCH_MAX_HTML_BYTES || 2_000_000
); // 2MB
const MAX_IMAGE_BYTES = Number(
  process.env.MCP_FETCH_MAX_IMAGE_BYTES || 10_000_000
); // 10MB
const DISABLE_SSRF_GUARD = process.env.MCP_FETCH_DISABLE_SSRF_GUARD === "1";

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map((v) => Number(v));
  if (
    parts.length !== 4 ||
    parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)
  )
    return false;
  const [a, b] = parts;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local
  if (a === 0) return true; // non-routable
  if (a >= 224 && a <= 239) return true; // multicast
  if (a >= 240) return true; // reserved
  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  return (
    lower === "::" ||
    lower === "::1" ||
    lower.startsWith("fe80:") || // link-local
    lower.startsWith("fc") || // fc00::/7 (fc/fd)
    lower.startsWith("fd") ||
    lower.startsWith("ff") // multicast
  );
}

function isNodeErrorWithCode(error: unknown): error is NodeJS.ErrnoException {
  return (
    error instanceof Error &&
    typeof (error as NodeJS.ErrnoException).code === "string"
  );
}

async function resolveAllIps(hostname: string): Promise<string[]> {
  try {
    const records = await dns.promises.lookup(hostname, {
      all: true,
      verbatim: true,
    });
    return records.map((r) => r.address);
  } catch {
    return [];
  }
}

async function isSafeUrl(
  input: string
): Promise<{ ok: true; url: URL } | { ok: false; reason: string }> {
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    return { ok: false, reason: "Invalid URL" };
  }
  if (!(u.protocol === "http:" || u.protocol === "https:")) {
    return { ok: false, reason: "Only http/https schemes are allowed" };
  }
  if (DISABLE_SSRF_GUARD) {
    return { ok: true, url: u };
  }
  const hostname = u.hostname;
  if (!hostname) return { ok: false, reason: "Missing hostname" };
  const isIp = net.isIP(hostname) !== 0;
  if (isIp) {
    if (net.isIP(hostname) === 4 && isPrivateIPv4(hostname)) {
      return { ok: false, reason: "IPv4 address is private/reserved" };
    }
    if (net.isIP(hostname) === 6 && isPrivateIPv6(hostname)) {
      return { ok: false, reason: "IPv6 address is private/reserved" };
    }
  } else {
    const lower = hostname.toLowerCase();
    if (
      lower === "localhost" ||
      lower.endsWith(".localhost") ||
      lower.endsWith(".local")
    ) {
      return { ok: false, reason: "Local hostnames are not allowed" };
    }
    const ips = await resolveAllIps(hostname);
    for (const ip of ips) {
      if (
        (net.isIP(ip) === 4 && isPrivateIPv4(ip)) ||
        (net.isIP(ip) === 6 && isPrivateIPv6(ip))
      ) {
        return {
          ok: false,
          reason: "Hostname resolves to private/reserved address",
        };
      }
    }
  }
  return { ok: true, url: u };
}

function withTimeout<T>(
  p: Promise<T>,
  ms: number,
  label = "request"
): Promise<T> {
  if (!ms || ms <= 0) return p;
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(
      () => reject(new Error(`${label} timed out after ${ms}ms`)),
      ms
    );
    p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e) => {
        clearTimeout(t);
        reject(e);
      }
    );
  });
}

async function safeFollowFetch(
  inputUrl: string,
  init: RequestInit = {},
  opts: { maxRedirects?: number; timeoutMs?: number } = {}
): Promise<{ response: FetchResponse; finalUrl: string }> {
  const maxRedirects = opts.maxRedirects ?? MAX_REDIRECTS;
  const timeoutMs = opts.timeoutMs ?? FETCH_TIMEOUT_MS;

  let current = inputUrl;
  for (let i = 0; i <= maxRedirects; i++) {
    const safe = await isSafeUrl(current);
    if (!safe.ok) throw new Error(`Blocked URL: ${safe.reason}`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const reqInit: RequestInit = {
        ...(init || {}),
        redirect: "manual",
        signal: controller.signal,
      };
      const resp: FetchResponse = await fetch(current, reqInit);
      clearTimeout(timer);
      if ([301, 302, 303, 307, 308].includes(resp.status)) {
        const loc = resp.headers.get("location");
        if (!loc)
          throw new Error(
            `Redirect status ${resp.status} without Location header`
          );
        const next = new URL(loc, current).toString();
        current = next;
        continue;
      }
      return { response: resp, finalUrl: current };
    } catch (e) {
      clearTimeout(timer);
      throw e;
    }
  }
  throw new Error("Too many redirects");
}

async function readTextLimited(
  resp: FetchResponse,
  maxBytes: number
): Promise<{ text: string; contentType: string }> {
  const ct = resp.headers.get("content-type") || "";
  const cl = resp.headers.get("content-length");
  if (cl && Number(cl) > maxBytes) {
    throw new Error(`Response too large (${cl} bytes > ${maxBytes})`);
  }
  const body = resp.body as Readable | null;
  if (!body || typeof body.on !== "function") {
    const text = await withTimeout(resp.text(), FETCH_TIMEOUT_MS, "read text");
    return { text, contentType: ct };
  }
  let size = 0;
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    body.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        body.destroy();
        reject(new Error(`Response exceeded limit (${maxBytes} bytes)`));
        return;
      }
      chunks.push(chunk);
    });
    body.on("end", () => resolve());
    body.on("error", (err: Error) => reject(err));
  });
  return { text: Buffer.concat(chunks).toString("utf8"), contentType: ct };
}

async function readBufferLimited(
  resp: FetchResponse,
  maxBytes: number
): Promise<Buffer> {
  const cl = resp.headers.get("content-length");
  if (cl && Number(cl) > maxBytes) {
    throw new Error(`Response too large (${cl} bytes > ${maxBytes})`);
  }
  const body = resp.body as Readable | null;
  if (!body || typeof body.on !== "function") {
    const ab = await withTimeout(
      resp.arrayBuffer(),
      FETCH_TIMEOUT_MS,
      "read buffer"
    );
    const buf = Buffer.from(ab);
    if (buf.length > maxBytes)
      throw new Error(`Response exceeded limit (${maxBytes} bytes)`);
    return buf;
  }
  let size = 0;
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    body.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        body.destroy();
        reject(new Error(`Response exceeded limit (${maxBytes} bytes)`));
        return;
      }
      chunks.push(chunk);
    });
    body.on("end", () => resolve());
    body.on("error", (err: Error) => reject(err));
  });
  return Buffer.concat(chunks);
}

/**
 * 通知客户端资源列表已更改
 */
async function notifyResourcesChanged(): Promise<void> {
  if (!serverInstance || !serverConnected) return;
  try {
    await serverInstance.sendResourceListChanged();
  } catch (error) {
    // When not connected to an MCP client, avoid noisy warnings in CI/tests
    if (serverConnected) {
      console.warn("Failed to notify resource list changed:", error);
    }
  }
}

/**
 * 扫描现有的下载文件并注册为资源
 */
async function scanAndRegisterExistingFiles(): Promise<void> {
  const homeDir = process.env.HOME || process.env.USERPROFILE || "";
  const baseDir = path.join(homeDir, "Downloads", "mcp-fetch");

  try {
    // 扫描日期目录
    const dateDirs = await fs.readdir(baseDir);

    for (const dateDir of dateDirs) {
      if (dateDir.startsWith(".")) continue; // 跳过 .DS_Store 等文件

      const datePath = path.join(baseDir, dateDir);
      const stats = await fs.stat(datePath);

      if (!stats.isDirectory()) continue;

      try {
        // 检查日期目录下的文件
        const files = await fs.readdir(datePath);

        for (const file of files) {
          if (!file.toLowerCase().endsWith(".jpg")) continue;

          const filePath = path.join(datePath, file);
          const fileStats = await fs.stat(filePath);

          if (!fileStats.isFile()) continue;

          // 生成资源URI (file:// scheme)
          const resourceUri = `file://${filePath}`;

          // 从文件名提取信息
          const baseName = path.basename(file, ".jpg");
          const isIndividual = file.includes("individual");

          const resourceName = `${dateDir}/${baseName}`;
          const description = `${isIndividual ? "Individual" : "Merged"} image from ${dateDir}`;

          const resource: ImageResource = {
            uri: resourceUri,
            name: resourceName,
            description,
            mimeType: "image/jpeg",
            filePath,
          };

          imageResources.set(resourceUri, resource);
        }

        // 同时检查子目录 (如果存在 individual/merged)
        const subDirs = ["individual", "merged"];

        for (const subDir of subDirs) {
          const subDirPath = path.join(datePath, subDir);

          try {
            const subFiles = await fs.readdir(subDirPath);

            for (const file of subFiles) {
              if (!file.toLowerCase().endsWith(".jpg")) continue;

              const filePath = path.join(subDirPath, file);
              const fileStats = await fs.stat(filePath);

              if (!fileStats.isFile()) continue;

              // 生成资源URI (file:// scheme)
              const resourceUri = `file://${filePath}`;

              // 从文件名提取信息
              const baseName = path.basename(file, ".jpg");
              const resourceName = `${dateDir}/${subDir}/${baseName}`;
              const description = `${subDir === "individual" ? "Individual" : "Merged"} image from ${dateDir}`;

              const resource: ImageResource = {
                uri: resourceUri,
                name: resourceName,
                description,
                mimeType: "image/jpeg",
                filePath,
              };

              imageResources.set(resourceUri, resource);
            }
          } catch (_error) {
            // 如果子目录不存在则跳过
          }
        }
      } catch (error) {
        console.warn(`Failed to scan directory ${datePath}:`, error);
      }
    }

    console.error(`Registered ${imageResources.size} existing image resources`);
  } catch (error) {
    if (isNodeErrorWithCode(error) && error.code === "ENOENT") {
      // No downloads directory yet; nothing to register on startup
      return;
    }
    console.warn("Failed to scan existing downloads:", error);
  }
}

const DEFAULT_USER_AGENT_AUTONOMOUS =
  "ModelContextProtocol/1.0 (Autonomous; +https://github.com/modelcontextprotocol/servers)";
// const DEFAULT_USER_AGENT_MANUAL =
//   "ModelContextProtocol/1.0 (User-Specified; +https://github.com/modelcontextprotocol/servers)";

/**
 * 从URL提取原始文件名
 */
function extractFilenameFromUrl(url: string): string {
  try {
    const urlObj = new URL(url);
    const pathname = urlObj.pathname;
    const filename = path.basename(pathname);

    // 文件名为空或没有扩展名时的默认处理
    if (!filename || !filename.includes(".")) {
      return "image.jpg";
    }

    return filename;
  } catch {
    return "image.jpg";
  }
}

// New structured API (optional)
const NewImagesSchema = z
  .union([
    z.boolean(),
    z.object({
      output: z.enum(["base64", "file", "both"]).optional(),
      layout: z.enum(["merged", "individual", "both"]).optional(),
      maxCount: z.number().int().min(0).max(10).optional(),
      startIndex: z.number().int().min(0).optional(),
      size: z
        .object({
          maxWidth: z.number().int().min(100).max(10000).optional(),
          maxHeight: z.number().int().min(100).max(10000).optional(),
          quality: z.number().int().min(1).max(100).optional(),
        })
        .optional(),
      originPolicy: z.enum(["cross-origin", "same-origin"]).optional(),
      saveDir: z.string().optional(),
    }),
  ])
  .optional();

const NewTextSchema = z
  .object({
    maxLength: z.number().int().positive().max(1000000).optional(),
    startIndex: z.number().int().min(0).optional(),
    raw: z.boolean().optional(),
  })
  .optional();

const NewSecuritySchema = z
  .object({
    ignoreRobotsTxt: z.boolean().optional(),
  })
  .optional();

const FetchArgsSchema = z.object({
  url: z
    .string()
    .url()
    .refine(
      (val) => {
        try {
          const u = new URL(val);
          return u.protocol === "http:" || u.protocol === "https:";
        } catch {
          return false;
        }
      },
      { message: "Only http/https URLs are allowed" }
    ),
  // legacy flat params (kept for backward compatibility)
  maxLength: z
    .union([z.number(), z.string()])
    .transform((val) => Number(val))
    .pipe(z.number().positive().max(1000000))
    .default(20000),
  startIndex: z
    .union([z.number(), z.string()])
    .transform((val) => Number(val))
    .pipe(z.number().min(0))
    .default(0),
  imageStartIndex: z
    .union([z.number(), z.string()])
    .transform((val) => Number(val))
    .pipe(z.number().min(0))
    .default(0),
  raw: z
    .union([z.boolean(), z.string()])
    .transform((val) =>
      typeof val === "string" ? val.toLowerCase() === "true" : val
    )
    .default(false),
  imageMaxCount: z
    .union([z.number(), z.string()])
    .transform((val) => Number(val))
    .pipe(z.number().min(0).max(10))
    .default(3),
  imageMaxHeight: z
    .union([z.number(), z.string()])
    .transform((val) => Number(val))
    .pipe(z.number().min(100).max(10000))
    .default(4000),
  imageMaxWidth: z
    .union([z.number(), z.string()])
    .transform((val) => Number(val))
    .pipe(z.number().min(100).max(10000))
    .default(1000),
  imageQuality: z
    .union([z.number(), z.string()])
    .transform((val) => Number(val))
    .pipe(z.number().min(1).max(100))
    .default(80),
  enableFetchImages: z
    .union([z.boolean(), z.string()])
    .transform((val) =>
      typeof val === "string" ? val.toLowerCase() === "true" : val
    )
    .default(false),
  allowCrossOriginImages: z
    .union([z.boolean(), z.string()])
    .transform((val) =>
      typeof val === "string" ? val.toLowerCase() === "true" : val
    )
    .default(true),
  ignoreRobotsTxt: z
    .union([z.boolean(), z.string()])
    .transform((val) =>
      typeof val === "string" ? val.toLowerCase() === "true" : val
    )
    .default(false),
  saveImages: z
    .union([z.boolean(), z.string()])
    .transform((val) =>
      typeof val === "string" ? val.toLowerCase() === "true" : val
    )
    .default(true),
  returnBase64: z
    .union([z.boolean(), z.string()])
    .transform((val) =>
      typeof val === "string" ? val.toLowerCase() === "true" : val
    )
    .default(false),
  // new structured params (optional)
  images: NewImagesSchema,
  text: NewTextSchema,
  security: NewSecuritySchema,
});

const ListToolsSchema = z.object({
  method: z.literal("tools/list"),
});

const CallToolSchema = z.object({
  method: z.literal("tools/call"),
  params: z.object({
    name: z.string(),
    arguments: z.record(z.unknown()).optional(),
  }),
});

function extractContentFromHtml(
  html: string,
  url: string
): ExtractedContent | string {
  const dom = new JSDOM(html, { url });
  const reader = new Readability(dom.window.document);
  const article = reader.parse();

  if (!article || !article.content) {
    return "<e>Page failed to be simplified from HTML</e>";
  }

  // Extract images from the article content only
  const articleDom = new JSDOM(article.content);
  const imgElements = Array.from(
    articleDom.window.document.querySelectorAll("img")
  );

  const images: Image[] = imgElements.map((img) => {
    const src = img.src;
    const alt = img.alt || "";
    const filename = extractFilenameFromUrl(src);
    return { src, alt, filename };
  });

  const turndownService = new TurndownService({
    headingStyle: "atx",
    codeBlockStyle: "fenced",
  });
  const markdown = turndownService.turndown(article.content);

  return { markdown, images, title: article.title ?? undefined };
}

async function fetchImages(
  images: Image[],
  baseOrigin: string,
  allowCrossOrigin: boolean
): Promise<(Image & { data: Buffer })[]> {
  const fetchedImages = [];
  for (const img of images) {
    try {
      const safe = await isSafeUrl(img.src);
      if (!safe.ok) continue;
      const srcOrigin = new URL(img.src).origin;
      if (!allowCrossOrigin && srcOrigin !== baseOrigin) continue;
      const { response } = await safeFollowFetch(
        img.src,
        {},
        { timeoutMs: FETCH_TIMEOUT_MS }
      );
      const imageBuffer = await readBufferLimited(response, MAX_IMAGE_BYTES);

      // 对于GIF图像只提取第一帧
      if (img.src.toLowerCase().endsWith(".gif")) {
        // GIF处理逻辑
      }

      fetchedImages.push({
        ...img,
        data: imageBuffer,
      });
    } catch (error) {
      console.warn(`Failed to process image ${img.src}:`, error);
    }
  }
  return fetchedImages;
}

/**
 * 将多张图片垂直合并为一张图片
 */
async function mergeImagesVertically(
  images: Buffer[],
  maxWidth: number,
  maxHeight: number,
  quality: number
): Promise<Buffer> {
  if (images.length === 0) {
    throw new Error("No images to merge");
  }

  // 获取各图片的元数据
  const imageMetas = await Promise.all(
    images.map(async (buffer) => {
      const metadata = await sharp(buffer).metadata();
      return {
        width: metadata.width || 0,
        height: metadata.height || 0,
        buffer,
      };
    })
  );

  // 计算最大宽度
  const width = Math.min(
    maxWidth,
    Math.max(...imageMetas.map((meta) => meta.width))
  );

  // 计算图片高度总和
  const totalHeight = Math.min(
    maxHeight,
    imageMetas.reduce((sum, meta) => sum + meta.height, 0)
  );

  // 创建新图片
  const composite = sharp({
    create: {
      width,
      height: totalHeight,
      channels: 4,
      background: { r: 255, g: 255, b: 255, alpha: 1 },
    },
  });

  // 放置各图片
  let currentY = 0;
  const overlays = [];

  for (const meta of imageMetas) {
    // 确保图片不超过画布高度
    if (currentY >= maxHeight) break;

    // 调整图片大小（仅在需要时）
    let processedImage = sharp(meta.buffer);
    if (meta.width > width) {
      processedImage = processedImage.resize(width);
    }

    const resizedBuffer = await processedImage.toBuffer();
    const resizedMeta = await sharp(resizedBuffer).metadata();

    overlays.push({
      input: resizedBuffer,
      top: currentY,
      left: 0,
    });

    currentY += resizedMeta.height || 0;
  }

  // 指定质量输出（使用JPEG代替PNG）
  return composite
    .composite(overlays)
    .jpeg({
      quality, // 指定JPEG质量（1-100）
      mozjpeg: true, // 使用mozjpeg进一步优化
    })
    .toBuffer();
}

// removed unused getImageDimensions helper to satisfy linter

/**
 * 将图片保存到基于日期的目录中，并返回文件路径
 */
async function saveImageToFile(
  imageBuffer: Buffer,
  sourceUrl: string,
  imageIndex: number = 0
): Promise<string> {
  // 获取当前日期的YYYY-MM-DD格式
  const now = new Date();
  const dateStr = now.toISOString().split("T")[0];

  // 保存目录: ~/Downloads/mcp-fetch/YYYY-MM-DD/merged/
  const homeDir = process.env.HOME || process.env.USERPROFILE || "";
  const baseDir = path.join(
    homeDir,
    "Downloads",
    "mcp-fetch",
    dateStr,
    "merged"
  );

  // 如果目录不存在则创建
  await fs.mkdir(baseDir, { recursive: true });

  // 生成文件名（URL的主机名 + 时间戳 + 索引）
  const urlObj = new URL(sourceUrl);
  const hostname = urlObj.hostname.replace(/[^a-zA-Z0-9]/g, "_");
  const timestamp = now
    .toISOString()
    .replace(/[:.]/g, "-")
    .split("T")[1]
    .split(".")[0];
  const filename = `${hostname}_${timestamp}_${imageIndex}.jpg`;

  const filePath = path.join(baseDir, filename);

  // 保存到文件
  await fs.writeFile(filePath, imageBuffer);

  // 注册为资源
  const resourceUri = `file://${filePath}`;
  const resourceName = `${dateStr}/merged/${filename}`;
  const description = `Merged image from ${sourceUrl} saved on ${dateStr}`;

  const resource: ImageResource = {
    uri: resourceUri,
    name: resourceName,
    description,
    mimeType: "image/jpeg",
    filePath,
  };

  imageResources.set(resourceUri, resource);

  // 通知客户端资源变更
  await notifyResourcesChanged();

  return filePath;
}

/**
 * 保存单张图片并注册为资源
 */
async function saveIndividualImageAndRegisterResource(
  imageBuffer: Buffer,
  sourceUrl: string,
  imageIndex: number,
  altText: string = "",
  originalFilename: string = "image.jpg"
): Promise<string> {
  // 获取当前日期的YYYY-MM-DD格式
  const now = new Date();
  const dateStr = now.toISOString().split("T")[0];

  // 保存目录: ~/Downloads/mcp-fetch/YYYY-MM-DD/individual/
  const homeDir = process.env.HOME || process.env.USERPROFILE || "";
  const baseDir = path.join(
    homeDir,
    "Downloads",
    "mcp-fetch",
    dateStr,
    "individual"
  );

  // 如果目录不存在则创建
  await fs.mkdir(baseDir, { recursive: true });

  // 使用原始文件名生成唯一文件名
  const ext = path.extname(originalFilename);
  const baseName = path.basename(originalFilename, ext);
  const safeBaseName = baseName.replace(/[^a-zA-Z0-9\-_]/g, "_");
  const filename = `${imageIndex}_${safeBaseName}${ext || ".jpg"}`;

  const filePath = path.join(baseDir, filename);

  // 保存到文件
  await fs.writeFile(filePath, imageBuffer);

  // 注册为资源
  const resourceUri = `file://${filePath}`;
  const resourceName = `${safeBaseName}_${imageIndex}`;
  const description = `${originalFilename}${altText ? ` (${altText})` : ""} from ${sourceUrl}`;

  const resource: ImageResource = {
    uri: resourceUri,
    name: resourceName,
    description,
    mimeType: "image/jpeg",
    filePath,
  };

  imageResources.set(resourceUri, resource);

  // 通知客户端资源变更
  await notifyResourcesChanged();

  return filePath;
}

async function checkRobotsTxt(
  url: string,
  userAgent: string
): Promise<boolean> {
  const { protocol, host } = new URL(url);
  const robotsUrl = `${protocol}//${host}/robots.txt`;

  try {
    const { response } = await safeFollowFetch(
      robotsUrl,
      { headers: { "User-Agent": userAgent } },
      { timeoutMs: Math.min(FETCH_TIMEOUT_MS, 8000) }
    );
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        throw new Error(
          "Autonomous fetching not allowed based on robots.txt response"
        );
      }
      return true; // Allow if no robots.txt
    }

    const { text: robotsTxt } = await readTextLimited(response, 100_000);
    const robots = robotsParser(robotsUrl, robotsTxt);

    if (!robots.isAllowed(url, userAgent)) {
      throw new Error(
        "The site's robots.txt specifies that autonomous fetching is not allowed. " +
          "Try manually fetching the page using the fetch prompt."
      );
    }
    return true;
  } catch (error) {
    // 如果robots.txt获取失败则允许访问
    if (error instanceof Error && error.message.includes("robots.txt")) {
      throw error;
    }
    return true;
  }
}

interface FetchResult {
  content: string;
  images: { data: string; mimeType: string; filePath?: string }[];
  remainingContent: number;
  remainingImages: number;
  title?: string;
}

async function fetchUrl(
  url: string,
  userAgent: string,
  forceRaw = false,
  options = {
    imageMaxCount: 3,
    imageMaxHeight: 4000,
    imageMaxWidth: 1000,
    imageQuality: 80,
    imageStartIndex: 0,
    startIndex: 0,
    maxLength: 20000,
    enableFetchImages: false,
    allowCrossOriginImages: true,
    saveImages: true,
    returnBase64: false,
  }
): Promise<FetchResult> {
  const { response, finalUrl } = await safeFollowFetch(url, {
    headers: { "User-Agent": userAgent },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch ${url} - status code ${response.status}`);
  }

  const { text, contentType } = await readTextLimited(response, MAX_HTML_BYTES);
  const isHtml =
    text.toLowerCase().includes("<html") || contentType.includes("text/html");

  if (isHtml && !forceRaw) {
    const result = extractContentFromHtml(text, finalUrl);
    if (typeof result === "string") {
      return {
        content: result,
        images: [],
        remainingContent: 0,
        remainingImages: 0,
      };
    }

    const { markdown, images, title } = result;
    const processedImages = [];

    if (
      options.enableFetchImages &&
      options.imageMaxCount > 0 &&
      images.length > 0
    ) {
      try {
        const startIdx = options.imageStartIndex;
        const baseOrigin = new URL(finalUrl).origin;
        let fetchedImages = await fetchImages(
          images.slice(startIdx),
          baseOrigin,
          options.allowCrossOriginImages ?? false
        );
        fetchedImages = fetchedImages.slice(0, options.imageMaxCount);

        if (fetchedImages.length > 0) {
          const imageBuffers = fetchedImages.map((img) => img.data);

          // 保存单张图片（新API: 仅当layout为individual/both且output为file/both时）
          type Layout = undefined | "merged" | "individual" | "both";
          type Output = undefined | "base64" | "file" | "both";
          const layout = (options as { layout?: Layout }).layout;
          const output = (options as { output?: Output }).output;
          const legacyMode =
            (options as { output?: Output }).output === undefined &&
            (options as { layout?: Layout }).layout === undefined;
          const shouldSaveIndividual = legacyMode
            ? true // 为了兼容性，在旧版API中始终保存
            : (layout === "individual" || layout === "both") &&
              (output === "file" || output === "both");

          if (shouldSaveIndividual) {
            for (let i = 0; i < fetchedImages.length; i++) {
              try {
                const img = fetchedImages[i];
                const optimizedIndividualImage = await sharp(img.data)
                  .jpeg({ quality: 80, mozjpeg: true })
                  .toBuffer();
                await saveIndividualImageAndRegisterResource(
                  optimizedIndividualImage,
                  finalUrl,
                  startIdx + i,
                  img.alt,
                  img.filename || "image.jpg"
                );
              } catch (error) {
                console.warn(`Failed to save individual image ${i}:`, error);
              }
            }
          }

          const mergedImage = await mergeImagesVertically(
            imageBuffers,
            options.imageMaxWidth,
            options.imageMaxHeight,
            options.imageQuality
          );

          // Base64编码前优化图片
          const optimizedImage = await sharp(mergedImage)
            .resize({
              width: Math.min(options.imageMaxWidth, 1200), // 限制最大宽度为1200px
              height: Math.min(options.imageMaxHeight, 1600), // 限制最大高度为1600px
              fit: "inside",
              withoutEnlargement: true,
            })
            .jpeg({
              quality: Math.min(options.imageQuality, 85), // 限制JPEG质量
              mozjpeg: true,
              chromaSubsampling: "4:2:0", // 使用色度子采样
            })
            .toBuffer();

          const base64Image = optimizedImage.toString("base64");

          // 文件保存功能（新API: 仅当output为file/both时）
          let filePath: string | undefined;
          const shouldSaveMerged = legacyMode
            ? options.saveImages
            : output === "file" || output === "both";
          if (shouldSaveMerged) {
            try {
              filePath = await saveImageToFile(
                optimizedImage,
                finalUrl,
                options.imageStartIndex
              );
              if (serverConnected) {
                console.error(`Image saved to: ${filePath}`);
              } else {
                console.log(`Image saved to: ${filePath}`);
              }
            } catch (error) {
              console.warn("Failed to save image to file:", error);
            }
          }

          processedImages.push({
            data:
              (legacyMode && options.returnBase64) ||
              (!legacyMode && (output === "base64" || output === "both"))
                ? base64Image
                : "",
            mimeType: "image/jpeg", // 将MIME类型改为JPEG
            filePath,
          });
        }
      } catch (err) {
        console.error("Error processing images:", err);
      }
    }

    return {
      content: markdown,
      images: processedImages,
      remainingContent: text.length - (options.startIndex + options.maxLength),
      remainingImages: Math.max(
        0,
        images.length - (options.imageStartIndex + options.imageMaxCount)
      ),
      title,
    };
  }

  return {
    content: `Content type ${contentType} cannot be simplified to markdown, but here is the raw content:\n${text}`,
    images: [],
    remainingContent: 0,
    remainingImages: 0,
    title: undefined,
  };
}

// 解析命令行参数
const args = process.argv.slice(2);
const IGNORE_ROBOTS_TXT = args.includes("--ignore-robots-txt");

// Server setup
const server = new Server(
  {
    name: "mcp-fetch",
    version: "1.6.2",
  },
  {
    capabilities: {
      tools: {},
      resources: {
        subscribe: true,
        listChanged: true,
      },
    },
  }
);

// Store server instance for notifications
serverInstance = server;

// 将命令行参数信息输出到日志
console.error(
  `Server started with options: ${IGNORE_ROBOTS_TXT ? "ignore-robots-txt" : "respect-robots-txt"}`
);

interface RequestHandlerExtra {
  signal: AbortSignal;
}

server.setRequestHandler(
  ListToolsSchema,
  async (_request: { method: "tools/list" }, _extra: RequestHandlerExtra) => {
    const tools = [
      {
        name: "imageFetch",
        description: `
擅长图片获取的MCP抓取工具。将文章正文转换为Markdown格式,并提取和优化页面中的图片。

API默认设置（指定images参数时）
- 图片: 获取并以BASE64格式返回（最多3张图片垂直合并为1张JPEG）
- 保存: 不保存（可选启用）
- 跨域: 允许（考虑CDN场景）

参数（新API）
- url: 目标URL（必需）
- images: true | { output, layout, maxCount, startIndex, size, originPolicy, saveDir }
  - output: "base64" | "file" | "both"（默认: base64）
  - layout: "merged" | "individual" | "both"（默认: merged）
  - maxCount/startIndex（默认: 3 / 0）
  - size: { maxWidth, maxHeight, quality }（默认: 1000/1600/80）
  - originPolicy: "cross-origin" | "same-origin"（默认: cross-origin）
- text: { maxLength, startIndex, raw }（默认: 20000/0/false）
- security: { ignoreRobotsTxt }（默认: false）

示例
{
  "url": "https://example.com",
  "images": true
}

{
  "url": "https://example.com",
  "images": { "output": "both", "layout": "both", "maxCount": 4 }
}
`,
        inputSchema: zodToJsonSchema(FetchArgsSchema),
      },
    ];
    return { tools };
  }
);

// MCP响应的类型定义
type MCPResponseContent =
  | { type: "text"; text: string }
  | { type: "image"; mimeType: string; data: string };

server.setRequestHandler(
  CallToolSchema,
  async (
    request: {
      method: "tools/call";
      params: { name: string; arguments?: Record<string, unknown> };
    },
    _extra: RequestHandlerExtra
  ) => {
    try {
      const { name, arguments: args } = request.params;

      if (name !== "imageFetch") {
        throw new Error(`Unknown tool: ${name}`);
      }

      const parsed = FetchArgsSchema.safeParse(args || {});
      if (!parsed.success) {
        throw new Error(`Invalid arguments: ${parsed.error}`);
      }

      const a = parsed.data as Record<string, unknown> & {
        url: string;
        images?: unknown;
        text?: { maxLength?: number; startIndex?: number; raw?: boolean };
        security?: { ignoreRobotsTxt?: boolean };
        // legacy fields (all optional)
        enableFetchImages?: boolean;
        saveImages?: boolean;
        returnBase64?: boolean;
        imageMaxWidth?: number;
        imageMaxHeight?: number;
        imageQuality?: number;
        imageStartIndex?: number;
        allowCrossOriginImages?: boolean;
        startIndex?: number;
        maxLength?: number;
        raw?: boolean;
        ignoreRobotsTxt?: boolean;
      };

      // Legacy mode detection: no new keys and/or legacy keys present
      const hasNewKeys =
        a.images !== undefined ||
        a.text !== undefined ||
        a.security !== undefined;
      const hasLegacyKeys =
        a.enableFetchImages !== undefined ||
        a.saveImages !== undefined ||
        a.returnBase64 !== undefined ||
        a.imageMaxWidth !== undefined ||
        a.imageMaxHeight !== undefined ||
        a.imageQuality !== undefined ||
        a.imageStartIndex !== undefined ||
        a.allowCrossOriginImages !== undefined ||
        a.startIndex !== undefined ||
        a.maxLength !== undefined ||
        a.raw !== undefined;

      const legacyMode =
        (!hasNewKeys && hasLegacyKeys) || (!hasNewKeys && !hasLegacyKeys);

      // Build fetch options with backward compatibility
      const fetchOptions: {
        imageMaxCount: number;
        imageMaxHeight: number;
        imageMaxWidth: number;
        imageQuality: number;
        imageStartIndex: number;
        startIndex: number;
        maxLength: number;
        enableFetchImages: boolean;
        allowCrossOriginImages: boolean;
        saveImages: boolean;
        returnBase64: boolean;
        raw?: boolean;
        output?: "base64" | "file" | "both";
        layout?: "merged" | "individual" | "both";
      } = {
        imageMaxCount: 3,
        imageMaxHeight: 4000,
        imageMaxWidth: 1000,
        imageQuality: 80,
        imageStartIndex: 0,
        startIndex: 0,
        maxLength: 20000,
        enableFetchImages: false,
        allowCrossOriginImages: true,
        saveImages: false,
        returnBase64: false,
        // new API additions (optional)
        output: undefined,
        layout: undefined,
      };

      if (legacyMode) {
        // Legacy defaults
        fetchOptions.startIndex =
          (a.startIndex as number | undefined) ?? fetchOptions.startIndex;
        fetchOptions.maxLength =
          (a.maxLength as number | undefined) ?? fetchOptions.maxLength;
        fetchOptions.raw = a.raw ?? false;
        fetchOptions.imageMaxCount =
          (a.imageMaxCount as number | undefined) ?? fetchOptions.imageMaxCount;
        fetchOptions.imageMaxHeight =
          (a.imageMaxHeight as number | undefined) ??
          fetchOptions.imageMaxHeight;
        fetchOptions.imageMaxWidth =
          (a.imageMaxWidth as number | undefined) ?? fetchOptions.imageMaxWidth;
        fetchOptions.imageQuality =
          (a.imageQuality as number | undefined) ?? fetchOptions.imageQuality;
        fetchOptions.imageStartIndex =
          (a.imageStartIndex as number | undefined) ??
          fetchOptions.imageStartIndex;
        fetchOptions.enableFetchImages = a.enableFetchImages ?? false;
        fetchOptions.allowCrossOriginImages = a.allowCrossOriginImages ?? true;
        fetchOptions.saveImages = a.saveImages ?? true; // keep previous default behavior
        fetchOptions.returnBase64 = a.returnBase64 ?? false;
        // In legacy mode we preserve prior implicit behavior: individual images saved when any saving occurs
        fetchOptions.output =
          fetchOptions.saveImages && fetchOptions.returnBase64
            ? "both"
            : fetchOptions.returnBase64
              ? "base64"
              : fetchOptions.saveImages
                ? "file"
                : undefined;
        fetchOptions.layout = "merged"; // merged remains primary; individual saving handled inside legacy path
      } else {
        // New API mode
        const imagesCfg = a.images;
        const textCfg = a.text || {};
        const securityCfg = a.security || {};

        fetchOptions.startIndex = textCfg.startIndex ?? fetchOptions.startIndex;
        fetchOptions.maxLength = textCfg.maxLength ?? fetchOptions.maxLength;
        fetchOptions.raw = textCfg.raw ?? false;

        // images: true | object | undefined (default true for new API?)
        const imagesEnabled =
          imagesCfg === undefined
            ? false
            : typeof imagesCfg === "boolean"
              ? imagesCfg
              : true;
        fetchOptions.enableFetchImages = imagesEnabled;

        if (imagesEnabled) {
          const cfg = (
            typeof imagesCfg === "object" && imagesCfg !== null
              ? (imagesCfg as any)
              : {}
          ) as {
            output?: "base64" | "file" | "both";
            layout?: "merged" | "individual" | "both";
            maxCount?: number;
            startIndex?: number;
            size?: { maxWidth?: number; maxHeight?: number; quality?: number };
            originPolicy?: "cross-origin" | "same-origin";
            saveDir?: string;
          };
          fetchOptions.imageMaxCount =
            cfg.maxCount ?? fetchOptions.imageMaxCount;
          fetchOptions.imageStartIndex =
            cfg.startIndex ?? fetchOptions.imageStartIndex;
          const size = cfg.size || {};
          fetchOptions.imageMaxWidth =
            size.maxWidth ?? fetchOptions.imageMaxWidth;
          fetchOptions.imageMaxHeight =
            size.maxHeight ?? fetchOptions.imageMaxHeight;
          fetchOptions.imageQuality = size.quality ?? fetchOptions.imageQuality;
          fetchOptions.allowCrossOriginImages =
            (cfg.originPolicy ?? "cross-origin") === "cross-origin";
          fetchOptions.saveImages =
            (cfg.output ?? "base64") === "file" ||
            (cfg.output ?? "base64") === "both";
          fetchOptions.returnBase64 =
            (cfg.output ?? "base64") === "base64" ||
            (cfg.output ?? "base64") === "both";
          fetchOptions.output = cfg.output ?? "base64";
          fetchOptions.layout = cfg.layout ?? "merged";
          // NOTE: saveDir (cfg.saveDir) is respected in save functions when implemented (future)
        }
        // security
        a.ignoreRobotsTxt = securityCfg.ignoreRobotsTxt ?? false;
      }

      // robots.txt respect unless ignored
      if (!a.ignoreRobotsTxt && !IGNORE_ROBOTS_TXT) {
        await checkRobotsTxt(a.url, DEFAULT_USER_AGENT_AUTONOMOUS);
      }

      const { content, images, remainingContent, remainingImages, title } =
        await fetchUrl(
          a.url,
          DEFAULT_USER_AGENT_AUTONOMOUS,
          fetchOptions.raw ?? false,
          fetchOptions
        );

      let finalContent = content.slice(
        fetchOptions.startIndex,
        fetchOptions.startIndex + fetchOptions.maxLength
      );

      // 添加剩余信息
      const remainingInfo = [];
      if (remainingContent > 0) {
        remainingInfo.push(`${remainingContent} characters of text remaining`);
      }
      if (remainingImages > 0) {
        remainingInfo.push(
          `${remainingImages} more images available (${fetchOptions.imageStartIndex + images.length}/${fetchOptions.imageStartIndex + images.length + remainingImages} shown)`
        );
      }

      if (remainingInfo.length > 0) {
        finalContent += `\n\n<e>Content truncated. ${remainingInfo.join(", ")}. Call the imageFetch tool with start_index=${
          fetchOptions.startIndex + fetchOptions.maxLength
        } and/or imageStartIndex=${fetchOptions.imageStartIndex + images.length} to get more content.</e>`;
      }

      // 创建MCP响应
      const responseContent: MCPResponseContent[] = [
        {
          type: "text",
          text: `Contents of ${parsed.data.url}${title ? `: ${title}` : ""}:\n${finalContent}`,
        },
      ];

      // 如果有图片则添加（仅当存在Base64数据时）
      for (const image of images) {
        if (image.data) {
          responseContent.push({
            type: "image",
            mimeType: image.mimeType,
            data: image.data,
          });
        }
      }

      // 如果有已保存的文件信息则添加
      const savedFiles = images.filter((img) => img.filePath);
      if (savedFiles.length > 0) {
        const fileInfoText = savedFiles
          .map((img, index) => `Image ${index + 1} saved to: ${img.filePath}`)
          .join("\n");

        responseContent.push({
          type: "text",
          text: `\n📁 Saved Images:\n${fileInfoText}`,
        });
      }

      return {
        content: responseContent,
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// Resources handlers
const ListResourcesSchema = z.object({
  method: z.literal("resources/list"),
});

const ReadResourceSchema = z.object({
  method: z.literal("resources/read"),
  params: z.object({
    uri: z.string(),
  }),
});

server.setRequestHandler(
  ListResourcesSchema,
  async (_request: { method: "resources/list" }) => {
    const resources = Array.from(imageResources.values()).map((resource) => ({
      uri: resource.uri,
      name: resource.name,
      description: resource.description,
      mimeType: resource.mimeType,
    }));

    return {
      resources,
    };
  }
);

server.setRequestHandler(
  ReadResourceSchema,
  async (request: { method: "resources/read"; params: { uri: string } }) => {
    const resource = imageResources.get(request.params.uri);

    if (!resource) {
      throw new Error(`Resource not found: ${request.params.uri}`);
    }

    try {
      const fileData = await fs.readFile(resource.filePath);
      const base64Data = fileData.toString("base64");

      return {
        contents: [
          {
            uri: resource.uri,
            mimeType: resource.mimeType,
            blob: base64Data,
          },
        ],
      };
    } catch (error) {
      throw new Error(`Failed to read resource file: ${error}`);
    }
  }
);

// Start server
async function runServer() {
  // 服务器启动时将现有文件注册为资源
  await scanAndRegisterExistingFiles();

  const transport = new StdioServerTransport();
  await server.connect(transport);
  serverConnected = true;
}

if (process.env.MCP_FETCH_DISABLE_SERVER !== "1") {
  runServer().catch((error) => {
    process.stderr.write(`Fatal error running server: ${error}\n`);
    process.exit(1);
  });
}

export { fetchUrl };
