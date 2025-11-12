# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**mcp-fetch** is a Model Context Protocol (MCP) server that provides web content fetching capabilities for AI assistants. It converts HTML pages to clean markdown using Mozilla Readability and optionally processes images using Sharp.

## Development Commands

```bash
# Build TypeScript to JavaScript
npm run build

# Type checking only (recommended before commits)
npm run typecheck

# Run unit tests
npm run unit

# Run all quality checks (unit tests + typecheck + format + biome check)
npm test

# Format code using Biome
npm run format

# Lint code using Biome
npm run lint

# Build and run the server
npm run dev

# Run the compiled server
npm start
```

## Architecture

### Single-File Design
- **Core logic**: All functionality is in `index.ts` (606 lines)
- **Type definitions**: External module types in `types.d.ts`
- This is intentional - the tool has focused scope and benefits from centralized logic

### Key Components
- **MCP Server**: Uses `@modelcontextprotocol/sdk` for protocol implementation
- **Content Pipeline**: HTML → Readability → Markdown → Pagination
- **Image Pipeline**: Fetch → JPEG conversion → Vertical merging → File saving → Optional Base64 encoding
- **Parameter Validation**: Zod schemas with automatic type conversion from string/number unions

### Dependencies Architecture
- **Content Processing**: `@mozilla/readability` + `jsdom` + `turndown` chain
- **Image Processing**: `sharp` for high-performance image operations
- **HTTP**: `node-fetch` for web requests
- **Compliance**: `robots-parser` for robots.txt checking

## Code Patterns

### Parameter Handling
The tool supports both legacy flat parameters and new structured API:

**Legacy API** (backward compatible):
```typescript
url: z.string(),
maxLength: z.union([z.string(), z.number()]).transform(Number).default(20000),
enableFetchImages: z.union([z.string(), z.boolean()]).transform(toBool).default(false)
```

**New API** (recommended):
```typescript
images: { output, layout, maxCount, startIndex, size, originPolicy, saveDir }
text: { maxLength, startIndex, raw }
security: { ignoreRobotsTxt }
```

Parameters use union types with Zod validation for automatic type conversion from string/number/boolean.

### Error Handling
Network operations include comprehensive error handling with specific error types for different failure scenarios.

### Image Optimization and File Saving
- Images are always converted to JPEG format with configurable quality (default 80)
- Multiple images are merged vertically when present
- **Default behavior**: Images are automatically saved to `~/Downloads/mcp-fetch/YYYY-MM-DD/` directory
- **Optional**: Base64 encoding for Claude Desktop display (enabled with `returnBase64: true`)
- **Filename format**: `hostname_HHMMSS_index.jpg`

## Configuration

### Biome (Linting/Formatting)
Configuration in `biome.json`:
- 2-space indentation
- Double quotes
- 80-character line width
- ES5 trailing commas
- Recommended rules enabled
- Uses modern Biome instead of ESLint + Prettier

### TypeScript
Configuration in `tsconfig.json`:
- Target: ES2022
- Module: NodeNext (ESM with .js extensions in imports)
- Strict mode enabled
- Output: `./dist`
- Module resolution: NodeNext

## Testing Strategy

Current approach:
1. Unit tests with Vitest (tests/image-fetch.test.ts)
2. TypeScript compilation for type safety
3. Biome for code quality
4. Manual testing via Claude Desktop integration

The `npm test` command runs: `npm run unit && npm run typecheck && npm run format && npm run check`

## Deployment

### 本地开发部署

#### 1. 构建项目
首先需要构建 TypeScript 项目：
```bash
npm run build
```

这将编译 TypeScript 代码到 `./dist` 目录。

#### 2. 添加到 Claude Desktop 配置

找到 Claude Desktop 配置文件位置：
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

在配置文件中添加 MCP 服务器配置：

```json
{
  "mcpServers": {
    "mcp-fetch": {
      "command": "node",
      "args": ["/Users/yangming/pycharm-workspace/mcp-fetch/dist/index.js"]
    }
  }
}
```

**注意**:
- 将路径 `/Users/yangming/pycharm-workspace/mcp-fetch/dist/index.js` 替换为你的实际项目路径
- 使用绝对路径以确保 Claude Desktop 能正确找到文件
- 每次修改代码后，需要重新运行 `npm run build` 来更新编译后的文件

#### 3. 重启 Claude Desktop

保存配置文件后，完全退出并重启 Claude Desktop 应用，新的 MCP 服务器将会加载。

#### 4. 验证安装

在 Claude Desktop 中，你应该能够使用 `imageFetch` 工具来获取网页内容和图片。

### npm 包部署

The tool is designed for npx usage:
```bash
npx -y @nicolas-is-nic/mcp-fetch
```

For Claude Desktop integration via npm package, add to MCP tools configuration:
```json
{
  "mcpServers": {
    "mcp-fetch": {
      "command": "npx",
      "args": ["-y", "@nicolas-is-nic/mcp-fetch"]
    }
  }
}
```

## Important Implementation Details

### Security Hardening (v1.5.1+)
- Only `http://` and `https://` URLs allowed
- SSRF protection: blocks private/loopback/link-local IPs
- Manual redirect handling with validation (max 3 hops)
- Request timeouts (default 12s, configurable via `MCP_FETCH_TIMEOUT_MS`)
- Response size limits: HTML up to 2MB, images up to 10MB

Environment variables for security tuning:
- `MCP_FETCH_TIMEOUT_MS` (default: 12000)
- `MCP_FETCH_MAX_REDIRECTS` (default: 3)
- `MCP_FETCH_MAX_HTML_BYTES` (default: 2000000)
- `MCP_FETCH_MAX_IMAGE_BYTES` (default: 10000000)
- `MCP_FETCH_DISABLE_SSRF_GUARD` (set to "1" to disable SSRF checks)

### Platform Specificity
- Designed for macOS (mentioned in README)
- Sharp binaries include Darwin ARM64 support

### Content Processing Limits
- Default maxLength: 20,000 characters
- Supports pagination via startIndex parameter
- Image processing disabled by default (performance consideration)

### Robots.txt Compliance
- Enabled by default for ethical web scraping
- Can be disabled with `ignoreRobotsTxt: true` parameter

## Common Development Workflow

1. Make code changes in `index.ts`
2. Run `npm run typecheck` to verify TypeScript
3. Run `npm run format` to ensure consistent formatting
4. Run `npm test` to run all validations (unit + typecheck + format + biome)
5. Test manually with `npm run dev` or via Claude Desktop integration

### MCP Resource Management
The server implements MCP resources protocol for saved images:
- Images saved to `~/Downloads/mcp-fetch/YYYY-MM-DD/` are registered as MCP resources
- On startup, `scanAndRegisterExistingFiles()` loads all existing images
- `notifyResourcesChanged()` notifies clients when new images are saved
- Resource URIs use `file://` scheme pointing to local JPEG files