# NekoLink 自动化发布指南 ฅ^•ﻌ•^ฅ

本项目集成了强大的 GitHub Actions 自动化发布系统，支持多环境、多架构的自动编译打包并发布到 GitHub Releases。

## 🚀 自动发布流程

主人的每次发布操作都非常简单，只需完成以下两步：

1. **更新版本号**：
   - 修改项目根目录下的 `VERSION` 文件。
   - 在 `CHANGELOG.md` 中添加对应的版本更新记录（建议使用 `## [x.y.z] - YYYY-MM-DD` 格式）。

2. **推送版本标签 (Tag)**：
   提交代码后，在终端执行以下命令（以 `v3.1.2` 为例）：
   ```bash
   git tag v3.1.2
   git push origin v3.1.2
   ```

一旦标签被推送到远程仓库，GitHub Actions 就会自动启动喵！

---

## 🛠 构建矩阵

自动化系统会同时在以下 **10 个组合环境下** 进行编译：

| 操作系统 | 架构 | 产物体积 |
| :--- | :--- | :--- |
| **Ubuntu 20.04** | amd64 / arm64 | `.deb` 包 |
| **Ubuntu 22.04** | amd64 / arm64 | `.deb` 包 |
| **Ubuntu 24.04** | amd64 / arm64 | `.deb` 包 |
| **Debian 12 (Bookworm)** | amd64 / arm64 | `.deb` 包 |
| **Debian 13 (Trixie)** | amd64 / arm64 | `.deb` 包 |

---

## 📝 自动日志提取

系统会自动解析 `CHANGELOG.md` 文件。它会根据 `VERSION` 文件中的版本号，自动提取从 `## [版本号]` 开始到下一个二级标题之前的内容，并将其作为 GitHub Release 的说明文字。

> [!TIP]
> 如果提取不到对应的版本日志，系统会默认使用 `CHANGELOG.md` 的前 20 行作为占位符。

---

## 📦 发布产物

编译完成后，您可以直接在仓库的 **Releases** 页面看到发布的 **Pre-release** 版本。

- 所有的 `.deb` 包都会带有对应环境的标识，例如：`NekoLink_3.1.1_debian-12_amd64.deb`。
- 如果构建失败，您可以点击 GitHub 顶部的 **Actions** 标签进入对应的 Workflow 查看错误日志。

---

祝主人发布的每一个版本都完美无瑕喵！( ⸝⸝•ᴗ•⸝⸝ )੭⁾⁾
