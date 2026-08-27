# stock-fasm

超小体积的 Windows 桌面股票行情监视器。功能完整的成品最小仅 **2222 字节**。

悬浮窗每秒刷新一次，显示多只股票的名称、现价、涨跌幅、最高、最低、成交量；背景完全透明，可拖动、可记忆位置。

## 成品一览

| 文件 | 体积 | 技术路线 |
|---|---|---|
| `stock32.exe` | 6144 B | C + Win32 API，MSVC 编译为 x86，链接器极限裁剪，无壳 |
| `stock_mini.exe` | 2222 B | 手写 x86 汇编 + Crinkler 压缩链接 |

两个 exe 功能完全一致。追求稳定兼容用 `stock32.exe`；追求极致体积用 `stock_mini.exe`（压缩壳 + 哈希导入可能被个别杀软启发式误报）。

## 功能特性

- 秒级实时行情，数据源为腾讯 `https://web.sqt.gtimg.cn/q=代码1,代码2,...`
- 六列显示：名称 / 现价 / 涨跌幅 / 最高 / 最低 / 成交量（万手），红涨绿跌
- 每列居右对齐，列间距 12px，窗口宽高精确贴合内容、无多余边距
- 背景完全透明（`UpdateLayeredWindow` 逐像素 alpha：背景 alpha=1 肉眼不可见但可点击，文字 alpha 由 ini 控制）
- 无边框、置顶、不出现在任务栏
- 左键拖动移动窗口；右键点击窗口退出，退出时自动把当前坐标写回 ini
- 股票代码、透明度、初始位置全部在 `stock.ini` 中配置

## 环境要求

- 运行：64 位 Windows（exe 为 x86 程序，经 WoW64 运行）
- 构建 stock32.exe：MSVC 编译器 + Windows SDK（需要 x86 目标库），如 VS Build Tools
- 构建 stock_mini.exe：`tools/` 目录已附带 fasm 1.73.35 与 Crinkler 3.0b（免安装），另需 Windows SDK 的 x86 版 `kernel32.lib`

## 构建 stock32.exe（C 版，6144 字节）

源码 `stock.c`，编译脚本 `build32.bat`。直接双击或在命令行运行：

```
build32.bat
```

脚本要点（对想复现细节的人）：

1. 脚本头部硬编码了本机的 MSVC 与 Windows SDK 路径（`VCBIN`、`SDK` 变量），**换机器请先改成你自己的路径**。注意：某些 Visual Studio 版本（如 VS18 BuildTools）的 `vcvarsall.bat x86` 不能正确切换 x86 目标（cl 仍是 x64 目标，链接报 C1905），所以脚本改为手动设置 `PATH`/`INCLUDE`/`LIB` 三个环境变量，直接指定 `bin\HostX64\x86` 工具链与 `lib\x86`、`um\x86` 库目录。
2. `cl /O1 /GS- /c stock.c`：最小体积优化、关安全检查。
3. `link` 关键参数：
   - `/NODEFAULTLIB /ENTRY:WinMainCRTStartup /SUBSYSTEM:WINDOWS` —— 不链接 CRT，自带入口
   - `/STUB:stub.bin` —— 使用 64 字节最小 DOS stub（`stub.bin`），PE 头从 1KB 压到 512B
   - `/ALIGN:512 /FILEALIGN:512`（有 LNK4108 警告，属预期）
   - `/MERGE:.rdata=.text /SECTION:.text,ERW` 等节合并
   - `/FIXED /DYNAMICBASE:NO /GUARD:NO` —— 去掉重定位与 CFG 开销
4. 源码侧的体积技巧：大缓冲区（32KB 接收缓冲等）用 `HeapAlloc` 运行时分配而非全局数组（避免全零初始化数据撑大文件）；用 `wsprintfA` 替代自写 itoa 等。

## 构建 stock_mini.exe（汇编版，2222 字节）

源码 `stock_coff.asm`（fasm 语法，MS COFF 输出），构建脚本 `buildmini.bat`：

```
buildmini.bat
```

两步：

1. `tools\fasm.exe stock_coff.asm stock_coff.obj` —— 汇编为 COFF 目标文件
2. `tools\Crinkler.exe ... stock_coff.obj kernel32.lib` —— Crinkler 压缩链接（`/UNSAFEIMPORT /COMPMODE:FAST /HASHSIZE:10` 等）。脚本中的 `LIB` 环境变量指向 x86 库目录（换机器先改 `VCBIN`/`SDK`），仅用于给 Crinkler 内置导入器提供 `kernel32.lib`。

汇编版的关键技术（感兴趣的可以读 `stock_coff.asm` 注释）：

- **零导入表**：不用 PE 导入表。运行时从 PEB 遍历模块链拿 kernel32/ntdll 基址，按 ror13 哈希遍历导出表解析全部 36 个 API（含 `LoadLibraryA` 加载 user32/gdi32/wininet）
- **BSS 零成本**：所有缓冲区位 VirtualSize > SizeOfRawData 的零填充尾部，不占文件字节
- x87 FPU 指令做浮点解析与格式化（`satof`/`dtoa2`），比整数拆分更省代码
- 绘制：`CreateDIBSection` + `TextOutA` + 逐像素 alpha 修正 + `UpdateLayeredWindow`
- 同目录的 `stock.asm` 是同一份逻辑的"纯手工 PE"变体（不压缩、头部手工排布），可用 `tools\fasm.exe stock.asm stock_t.exe` 直接汇编出 3684B 的可运行 exe，供研究参考

## stock.ini 用法

exe 同目录下放 `stock.ini`（ANSI/GBK 或 UTF-8 均可）：

```ini
[stock]
; 股票代码，多只之间用半角逗号或全角逗号分隔（空格、换行会被忽略）
; 代码需带市场前缀：sh=上海，sz=深圳，最多 32 只
codes=sh603663,sz300502,sz002734,sz300058,sz000988,sh603067,sz000792,sh601020
; 窗口透明度 10-255（255=不透明；数值作用于文字，背景始终全透明）
opacity=50
; 窗口初始位置（右键关闭时会自动把当前位置写回这里）
x=100
y=100
```

## 使用

- 双击 exe 启动；窗口初始位置由 ini 的 `x`/`y` 决定
- **左键按住拖动**移动窗口（整个窗口任意位置都可拖动，包括看起来"透明"的区域）
- **右键点击窗口**退出，并把当前位置写回 ini，下次启动原位恢复
- 修改 ini 后重启 exe 生效

## 注意

- 行情数据来自腾讯免费行情接口，字段布局：1=名称 3=现价 4=昨收 6=成交量(手) 33=最高 34=最低
- `stock_mini.exe` 使用了压缩壳与哈希导入，属于杀软启发式扫描的高危特征；如遇误报，换用无壳的 `stock32.exe`
- 窗口透明度设得很低（如 20 以下）时文字会非常淡，属预期行为
