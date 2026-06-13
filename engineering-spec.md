# Fabric Planner — 工程规格书 v1.0(交付 AI 开发用)

> 本文档是施工图,不是建议书。开发者(Opus / Claude Code)必须按本文档的文件结构、分层规则、函数签名实现;任何偏离需先在 PR 描述中说明理由。行为基准参考随附的 `network-designer.jsx` 原型 —— 规则引擎的输出必须与原型种子场景一致(见 §10 验收)。

---

## 0. 硬性原则(违反即返工)

1. **连线只能由规则引擎生成**。不提供任何"手工创建单条 link"的 API 或 UI。特例场景用"单对设备的 cross 规则"覆盖。
2. **rules/ 与 derive/ 两个包是纯函数层**:禁止 import sqlalchemy、fastapi、任何 IO。输入快照 DTO,输出计划/视图 DTO。
3. **分层依赖只允许单向**:`api → services → (rules | derive | repo) → db`。repo 不得调用 services;rules 不得调用 repo。
4. **数据库可移植**:只使用 SQLite 与 PostgreSQL 都支持的列类型(见 §4.1)。切库 = 改 `DATABASE_URL`,零代码修改。
5. **每个写 API 都在单个事务内完成**,失败全回滚;删 link_group 必须级联复位端口状态。
6. 不引入本文档之外的框架/库/服务(没有 Redis、没有 Celery、没有第二个服务进程)。

## 1. 程序清单(一共 3 个可运行程序)

| # | 程序 | 技术 | 进程形态 |
|---|---|---|---|
| P1 | `backend` | Python 3.12 + FastAPI 0.115 + SQLAlchemy 2.0 + Pydantic v2 + Alembic + openpyxl | `uvicorn app.main:app`,1 个进程 |
| P2 | `frontend` | Node 20 + Vite 5 + React 18 + TypeScript 5 + @xyflow/react 12 + elkjs 0.9 + Zustand 4 + TanStack Query 5 | 开发 `vite dev`,生产 nginx 静态托管 |
| P3 | `cli`(可选,M1 顺带) | `python -m app.cli` | 导入 devicetype YAML、导出 project 的命令行入口,复用 P1 的包 |

数据库:**验证期 SQLite 单文件 `data/fabric.db`**;生产换 PostgreSQL 16。没有其他存储。

## 2. 仓库结构(文件级,每个文件一行职责)

```
fabric-planner/
├── docker-compose.yml            # backend + frontend(生产);sqlite 阶段无 db 容器
├── Makefile                      # make dev / test / migrate / seed / export-openapi
├── prototype/network-designer.jsx  # 行为基准原型(只读,不参与构建)
│
├── backend/
│   ├── pyproject.toml            # 依赖锁定(uv 或 poetry)
│   ├── alembic/                  # 迁移(从 M1 起就用,目标 sqlite)
│   └── app/
│       ├── main.py               # FastAPI 实例、挂载 routers、CORS、异常处理器
│       ├── config.py             # Settings(DATABASE_URL 默认 sqlite:///data/fabric.db)
│       ├── db.py                 # engine/session 工厂;sqlite 时执行 PRAGMA foreign_keys=ON
│       │
│       ├── catalog/              # ── 设备型号库 ──
│       │   ├── models.py         # ORM: DeviceModel, PortTemplate
│       │   ├── schemas.py        # Pydantic: DeviceModelOut, PortTemplateIn ...
│       │   ├── importer.py       # parse_devicetype_yaml(text) -> DeviceModelIn(纯函数)
│       │   ├── repo.py           # CatalogRepo: upsert_model, list_models, get_model
│       │   └── router.py         # /catalog/*
│       │
│       ├── design/               # ── 设计/域树/设备/接口 CRUD ──
│       │   ├── models.py         # ORM: Design, Block, BlockRelation, Device, Interface
│       │   ├── schemas.py        # Pydantic 请求/响应
│       │   ├── repo.py           # DesignRepo(见 §5 关键方法签名)
│       │   ├── service.py        # DesignService: 建设备时按模板展开 interface 等编排
│       │   └── router.py         # /designs/* /blocks/* /devices/* /interfaces/*
│       │
│       ├── rules/                # ── 规则引擎(纯函数,零 IO)──
│       │   ├── types.py          # DTO: PortSnap, DeviceSnap, LinkGroupParams, Plan...
│       │   ├── patterns.py       # PATTERNS 注册表: full_mesh / ring / cross_full_mesh
│       │   ├── allocator.py      # PortAllocator: 端口分配 + 自动 breakout
│       │   ├── validators.py     # precheck: 速率支持、容量预检
│       │   └── engine.py         # plan_link_group(snapshot, params) -> Plan
│       │
│       ├── links/                # ── 连线组的落库编排 ──
│       │   ├── models.py         # ORM: LinkGroup, Link
│       │   ├── schemas.py
│       │   ├── service.py        # LinkService: preview / commit / delete_group
│       │   └── router.py         # /designs/{id}/link-groups/*
│       │
│       ├── derive/               # ── 派生视图(纯函数)──
│       │   ├── bom.py            # bom_for(devices, links, scope) -> BomOut
│       │   ├── patching.py       # patching_rows(links, devices) -> list[PatchRow]
│       │   ├── topology.py       # topology_for(block_ids, ...) -> {nodes, edges}
│       │   └── diff.py           # diff_links(snapshot_a, snapshot_b) -> {added, removed}
│       │
│       ├── export/
│       │   ├── xlsx.py           # write_patching_bom_xlsx(rows, bom) -> bytes(openpyxl)
│       │   └── router.py         # /designs/{id}/patching.xlsx 等
│       │
│       ├── project/              # ── 整体项目导入导出 ──
│       │   ├── format.py         # FABPROJ_SCHEMA_VERSION=1;Pydantic: ProjectFile
│       │   ├── exporter.py       # export_project(design_id) -> ProjectFile
│       │   ├── importer.py       # import_project(ProjectFile) -> new design_id(ID 重映射)
│       │   └── router.py         # GET /designs/{id}/export  POST /projects/import
│       │
│       ├── snapshot/             # M5
│       │   ├── models.py         # ORM: Snapshot(payload=ProjectFile JSON)
│       │   ├── service.py        # take(design_id), diff(a,b) -> 调 derive.diff
│       │   └── router.py
│       │
│       └── tests/
│           ├── test_allocator.py     # Hypothesis 属性测试(见 §10)
│           ├── test_engine_seed.py   # 重放原型 5 个种子场景
│           ├── test_project_roundtrip.py  # 导出→导入→再导出,字节级等价(除 id/时间)
│           └── test_api_flows.py     # httpx 端到端
│
└── frontend/
    ├── package.json
    └── src/
        ├── api/
        │   ├── client.ts         # openapi-typescript 生成(make export-openapi 后生成)
        │   └── hooks.ts          # useDesign, useBlocks, usePreviewLinkGroup ... (TanStack Query)
        ├── store/
        │   └── uiStore.ts        # Zustand:当前 designId、选中域/设备、画布模式(服务器数据不放这里)
        ├── pages/
        │   ├── ProjectPage.tsx   # 项目列表 + 新建/打开/导出 .fabproj.json/导入
        │   ├── HldPage.tsx       # React Flow 画布
        │   ├── LldPage.tsx       # 域树 + 设备 + 规则表单 + LLD 图 + 设备抽屉
        │   ├── ComboPage.tsx     # 框选组合图
        │   ├── BomPage.tsx       # 按域 BOM
        │   └── PatchingPage.tsx  # patching 表 + 导出
        ├── components/
        │   ├── canvas/BlockNode.tsx        # RF 自定义节点(含子域列表)
        │   ├── canvas/HldCanvas.tsx        # 节点拖拽→PATCH /blocks/{id} 位置;连线模式→POST relation
        │   ├── lld/DomainTree.tsx          # 递归域树(GET /designs/{id}/blocks?tree=1)
        │   ├── lld/RuleForm.tsx            # 表单变化 300ms 防抖调 preview,展示将生成/将拆分/警告
        │   ├── lld/DeviceDrawer.tsx        # GET /devices/{id}/interfaces;breakout/restore 按钮
        │   ├── lld/LldDiagram.tsx          # elkjs 布局 + SVG 渲染(沿用原型弧线/平行偏移逻辑)
        │   └── common/SpeedLegend.tsx
        └── App.tsx               # 路由:/p/:designId/(hld|lld|combo|bom|patching)
```

## 3. 分层与调用关系

```
┌────────────┐   HTTP/JSON    ┌──────────────────────────────────────────┐
│  frontend  │ ─────────────▶ │ api(router 层,只做参数校验和编排转发) │
└────────────┘                └───────────────┬──────────────────────────┘
                                              ▼
                              ┌──────────────────────────────┐
                              │ services(事务边界在这一层) │
                              └───┬──────────────┬───────────┘
                        加载快照  ▼              ▼  纯计算
                       ┌──────────────┐   ┌─────────────────┐
                       │ repo(ORM)  │   │ rules / derive  │
                       └──────┬───────┘   │  (零 IO 纯函数)│
                              ▼           └─────────────────┘
                       ┌──────────────┐
                       │ SQLite / PG  │
                       └──────────────┘
依赖方向只允许向下;rules/derive 对左边一无所知。
```

三条关键时序(必须按此实现):

```
A. 生成连线组(preview 与 commit 共用同一计划函数)
   POST /designs/{d}/link-groups/preview
     router → LinkService.preview(d, params)
       → DesignRepo.load_device_snapshots(d, block_ids)   # ORM → list[DeviceSnap]
       → rules.engine.plan_link_group(snaps, params)      # 纯函数 → Plan
       → return PlanOut(不落库)
   POST /designs/{d}/link-groups
     router → LinkService.commit(d, params)
       → 同上两步得到 Plan;Plan.error 非空则 409
       → 事务内 DesignRepo.apply_plan(d, group_row, Plan):
            1) INSERT link_group
            2) 对每个 BreakoutPlan:父 interface.state='broken_out',INSERT 4 个子 interface(parent_if=父)
            3) 对每个 LinkPlan:INSERT link(a_if,b_if 由 dev+port 名解析),两端 interface.state='used'
       → commit;返回 group + links

B. 删除连线组
   DELETE /link-groups/{g}
     → LinkService.delete_group:事务内删 link → 两端 interface.state='free'
       → 自动创建且子口全 free 的 breakout 不自动恢复(与原型一致,由用户在设备抽屉手动恢复)

C. 项目导出/导入
   GET /designs/{d}/export → exporter.export_project(d) → ProjectFile(JSON 下载,文件名 {name}.fabproj.json)
   POST /projects/import(multipart 上传)
     → importer.import_project:校验 schema_version → 事务内按依赖顺序插入
       (device_models → port_templates → design → blocks → relations → devices
        → interfaces → link_groups → links),旧 id→新 id 用映射表重写全部外键
     → 返回 new design_id,前端跳转打开
```

## 4. 数据层

### 4.1 SQLite 验证方案(硬规定)

`DATABASE_URL=sqlite:///data/fabric.db`。为保证日后零成本切 Postgres:列类型只许用 `String/Text/Integer/Boolean/DateTime/JSON`(SQLAlchemy 的 `sa.JSON` 在两库都工作);**禁止** `ARRAY/INET/CIDR/UUID` 原生类型 —— `breakout_speeds` 存 JSON 数组,IP/前缀存 TEXT(校验放 Pydantic),主键用 `String(26)` 存 ULID(`python-ulid`,应用层生成,导入导出时重映射友好)。`db.py` 中 sqlite 连接事件里执行 `PRAGMA foreign_keys=ON`。Alembic 从 M1 启用,迁移脚本同样只用上述类型。SQLite 单写者特性在验证期(单人使用)不构成问题;并发协作是切 PG 之后的事。

### 4.2 表(与上一版 plan 一致,补齐列细节)

```sql
design          (id PK, name, schema_version INT, created_at, updated_at)
block_template  (key PK, label, color, allowed_children JSON)   -- 种子: core/external/compute/backup/oob/dwdm/sub
block           (id PK, design_id FK, template_key FK, name,
                 parent_id FK→block NULL, pos_x REAL, pos_y REAL, sort INT)
block_relation  (id PK, design_id FK, a_block FK, b_block FK, UNIQUE(design_id,a_block,b_block))
device_model    (id PK, vendor, model UNIQUE, port_prefix, meta JSON)
port_template   (id PK, model_id FK, idx_from INT, idx_to INT,
                 speed_g INT, media, breakout_speeds JSON)      -- 如 [25]
device          (id PK, design_id FK, block_id FK, model_id FK, name, seq INT)
interface       (id PK, device_id FK, name, speed_g INT, media,
                 parent_if FK→interface NULL,
                 state TEXT CHECK(state IN ('free','used','broken_out','reserved')),
                 sort INT,                                      -- 模板展开顺序,分配器排序依据
                 UNIQUE(device_id, name))
link_group      (id PK, design_id FK, owner_block FK, kind TEXT, params JSON, label)
link            (id PK, group_id FK, a_if FK UNIQUE, b_if FK UNIQUE, speed_g INT, media, tag)
snapshot        (id PK, design_id FK, label, payload JSON, created_at)
```

## 5. 关键函数签名(必须照抄)

```python
# rules/types.py ── 全部 frozen dataclass 或 Pydantic(选一种,全包统一)
class PortSnap:    name: str; speed_g: int; media: str; state: str
                   parent: str | None; breakout_speeds: tuple[int, ...]; sort: int
class DeviceSnap:  id: str; name: str; model: str; ports: list[PortSnap]
class LinkGroupParams:
                   kind: Literal["internal","cross"]
                   owner_block: str; target_block: str | None
                   pattern: Literal["full_mesh","ring"] | None   # internal 用
                   per_pair: int; speed_g: int; allow_breakout: bool; tag: str
class LinkPlan:    a_dev: str; a_port: str; b_dev: str; b_port: str; speed_g: int; tag: str
class BreakoutPlan: dev: str; parent_port: str; child_speed_g: int
class Plan:        links: list[LinkPlan]; breakouts: list[BreakoutPlan]
                   warnings: list[str]; error: str | None

# rules/patterns.py
PairFn = Callable[[list[DeviceSnap], list[DeviceSnap] | None], list[tuple[DeviceSnap, DeviceSnap]]]
PATTERNS: dict[str, PairFn]          # "full_mesh" "ring" "cross_full_mesh"
# ring 语义:n>=3 成环含回绕;n==2 仅 1 对;n<2 报错(与原型一致)

# rules/allocator.py
class PortAllocator:
    def __init__(self, devices: list[DeviceSnap], allow_breakout: bool): ...
    def alloc(self, dev_id: str, speed_g: int, direction: Literal["desc","asc"]) -> PortSnap | None
        # desc: peer/uplink 从 sort 最大往小;asc: downlink 从小往大
        # 原生口用尽且 allow_breakout:取方向上第一个可拆且 free 的原生口,
        # 登记 BreakoutPlan,生成 4 个子口(命名 f"{parent}/{1..4}"),返回第 1 个子口
    def planned_breakouts(self) -> list[BreakoutPlan]

# rules/validators.py
def supports_speed(model_ports: list[PortSnap], speed_g: int, allow_breakout: bool) -> bool
def capacity_precheck(devices, pairs, params) -> str | None   # 端口总量不够直接给 error,禁止生成一半

# rules/engine.py ── 引擎唯一入口
def plan_link_group(devices_a: list[DeviceSnap],
                    devices_b: list[DeviceSnap] | None,
                    params: LinkGroupParams) -> Plan
# 内部顺序:validators.capacity_precheck → PATTERNS[...]配对 → 逐对×per_pair 调 allocator
# 方向规则:internal 双端 desc;cross 时 A 端(发起方/子域)desc、B 端(目标/父域)asc

# design/repo.py(节选)
class DesignRepo:
    def load_device_snapshots(self, design_id: str, block_ids: list[str]) -> list[DeviceSnap]
    def expand_interfaces(self, device_id: str) -> int        # 按 port_template 批量 INSERT,返回行数
    def apply_plan(self, design_id: str, group: LinkGroup, plan: Plan) -> list[Link]  # 见时序 A
    def block_subtree_ids(self, block_id: str) -> list[str]   # 递归 CTE

# derive/bom.py
def bom_for(devices, links, ifaces_by_id, scope_block_ids: set[str] | None,
            include_children: bool) -> BomOut
# 光模块统计规则(与原型 countOptics 一致):端点归属设备所在域;
# breakout 子口端点按"父口 1 个分支模块"归并,绝不按 4 个子口重复计数

# project/exporter.py / importer.py
def export_project(session, design_id: str) -> ProjectFile          # 内嵌引用到的 device_model+port_template
def import_project(session, pf: ProjectFile) -> str                 # 返回新 design_id;ULID 全量重映射
```

## 6. REST API 契约(全部挂 /api/v1)

| 方法 路径 | 入参 | 出参 | 说明 |
|---|---|---|---|
| GET/POST `/designs` · GET/PATCH/DELETE `/designs/{id}` | | | PATCH 含 name |
| GET `/designs/{id}/blocks?tree=1` | | 嵌套树 | |
| POST `/designs/{id}/blocks` | {template_key,name,parent_id?} | Block | |
| PATCH `/blocks/{id}` | {name?,pos_x?,pos_y?,parent_id?} | | 拖拽落点也走这里 |
| DELETE `/blocks/{id}` | | | 级联子域/设备/线,复位无关端口 |
| POST/DELETE `/designs/{id}/relations` | {a_block,b_block} | | HLD 虚线 |
| POST `/blocks/{id}/devices` | {model_id,count} | Device[] | 事务内 expand_interfaces |
| GET `/devices/{id}/interfaces?state=&speed=` | | Interface[](含 peer 信息) | 设备抽屉数据源 |
| POST `/interfaces/{id}/breakout` {child_speed_g} · POST `/interfaces/{id}/restore` | | | restore 校验子口全 free |
| POST `/designs/{id}/link-groups/preview` | LinkGroupParams | Plan | 不落库 |
| POST `/designs/{id}/link-groups` | LinkGroupParams | Group+Links | 409 带 error 文案 |
| DELETE `/link-groups/{gid}` | | | |
| GET `/designs/{id}/topology?blocks=a,b,c` | | {nodes,edges} | 框选组合图 |
| GET `/designs/{id}/bom?block=&include_children=` | | {devices:[],optics:[]} | |
| GET `/designs/{id}/patching?block=` · GET `.../patching.xlsx` | | rows / 文件流 | xlsx 双 sheet(Patching+BOM) |
| GET `/designs/{id}/export` | | ProjectFile 下载 | Content-Disposition: {name}.fabproj.json |
| POST `/projects/import` | multipart file | {design_id} | |
| POST `/designs/{id}/snapshots` · GET `/snapshots/{a}/diff/{b}` | | | M5 |
| POST `/catalog/import-devicetype` | YAML 文本/文件 | DeviceModel | |

## 7. Project 文件格式 `.fabproj.json`(format.py 固化)

```jsonc
{
  "format": "fabproj",
  "schema_version": 1,                  // importer 只接受 <= 当前版本,留升迁钩子
  "exported_at": "2026-06-13T10:00:00Z",
  "design": { "id": "01J...", "name": "TOKYO-DC1", "schema_version": 1 },
  "block_templates": [ { "key": "core", "label": "DC Core", "color": "#F2762E", "allowed_children": ["sub"] } ],
  "device_models": [ {                  // 内嵌全部被引用型号 → 文件离线自洽,换环境可开
      "id": "01J...", "vendor": "Cisco", "model": "N9K-C93180YC-FX3", "port_prefix": "Eth1/",
      "port_templates": [ { "idx_from":1,"idx_to":48,"speed_g":25,"media":"SFP28","breakout_speeds":[] },
                          { "idx_from":49,"idx_to":54,"speed_g":100,"media":"QSFP28","breakout_speeds":[25] } ] } ],
  "blocks":          [ { "id":"01J...","template_key":"external","name":"EXTERNAL","parent_id":null,"pos_x":560,"pos_y":55,"sort":0 } ],
  "block_relations": [ { "a_block":"...","b_block":"..." } ],
  "devices":         [ { "id":"...","block_id":"...","model_id":"...","name":"EXT-RTR-01","seq":1 } ],
  "interfaces":      [ { "id":"...","device_id":"...","name":"Eth1/1","speed_g":100,"media":"QSFP28",
                         "parent_if":null,"state":"used","sort":1 } ],   // 全量导出含 breakout 子口与状态
  "link_groups":     [ { "id":"...","owner_block":"...","kind":"cross","label":"...","params":{...} } ],
  "links":           [ { "id":"...","group_id":"...","a_if":"...","b_if":"...","speed_g":100,"media":"SMF","tag":"uplink" } ],
  "snapshots":       []                 // 可选携带
}
```

导入规则:整文件先过 Pydantic 校验;所有 id 重新生成 ULID 并维护 old→new 映射重写外键;`device_model` 按 `vendor+model` 去重(库里已有同名型号则复用库内 id,但若 port_templates 不一致 → 以文件为准新建带后缀的型号并警告)。导出→导入→导出的两份文件,除 id 与时间戳外必须深度相等(测试覆盖,见 §10)。

前端 ProjectPage:列出 `/designs`,打开即恢复;"导出项目"下载 json;"导入项目"上传后跳转。另:HLD 画布所有位置变更即时 PATCH,**没有"保存"按钮的概念 —— 服务端永远是最新状态**,导出文件只是备份/交换载体。

## 8. 前端实现要点

服务器数据一律走 TanStack Query(缓存键 `['design',id,...]`,写操作后 invalidate);Zustand 只放 UI 态(选中项、连线模式、抽屉开关)。RuleForm 对 preview 接口 300ms 防抖,渲染三栏:将生成 N 根线 / 将拆分哪些口 / 警告或错误(error 时禁用提交按钮)。LldDiagram 的弧线、平行线偏移、端口标签逻辑直接移植原型(原型函数 → TS util),elkjs 仅用于设备多于 8 台时的分层布局,少量设备沿用原型的均匀排布。HldCanvas 的域节点用 RF 的 parent/extent 实现"子域显示在父块内"为 V1.1 增强,V1 先沿用原型样式(顶层块 + 子域名列表)。

## 9. 给 Opus 的施工顺序(每步有验收,顺序不可调换)

1. **S1 骨架**:Makefile、config、db.py、空 FastAPI、Vite 空页面、CI(pytest+tsc)。验收:`make dev` 起两端,`GET /api/v1/health` 200。
2. **S2 catalog+design 数据层**:全部 ORM + Alembic 初版 + 种子脚本(内置 §10 的 5 个型号与 block_template)。验收:`make seed` 后 sqlite 内数据正确;建 4 台设备 expand_interfaces 行数=4×36。
3. **S3 rules 包**:types/patterns/allocator/validators/engine + 全部单测。验收:§10 的种子重放与属性测试全绿。**此步不碰数据库。**
4. **S4 links 服务**:preview/commit/delete + apply_plan 事务。验收:test_api_flows 走通时序 A/B;删组后 interface 状态全部复位。
5. **S5 derive+export**:bom/patching/topology + xlsx。验收:xlsx 双 sheet 数字与 API JSON 一致;breakout 归并计数正确。
6. **S6 project 导入导出**:format/exporter/importer + roundtrip 测试。验收:导出→清库→导入→再导出深度相等。
7. **S7 前端**:按 §2 文件清单实现五页 + ProjectPage。验收:浏览器里完整复刻原型种子场景(含三层域树与 breakout),刷新页面状态不丢,导出再导入打开一切如初。
8. **S8 snapshot+diff(M5)**。验收:改一条规则后 diff 输出精确的新增/删除线清单。

禁止事项清单(开发中自查):不加消息队列/缓存/第二服务;不在 router 里写业务逻辑;不在 rules 里查库;不绕过 plan 直接 INSERT link;不使用 SQLite 不支持的列类型;不引入未列出的 npm/pip 依赖(UI 组件库也不要,样式沿用原型的轻量 CSS)。

## 10. 测试与验收基准

种子场景(test_engine_seed.py,数据照抄原型 buildSeed):① DC-CORE 4×7280CR3 full-mesh 1×400G → 6 根线,端口 Et36 起降序;② EXTERNAL 2×9336C → CORE 100G 每对 1 根 → 8 根,CORE 端 Et1 起升序;③ INTERNET→EXTERNAL(父域)100G → 4 根;④ INET-ACCESS 2×93180 → INTERNET 25G 每对 2 根 → 8 根,且 INET-DIST 两台各自动 breakout 恰好 1 个 100G 口、子口 Eth1/1/1..4 全用满;⑤ COMPUTE→CORE 100G → 4 根。断言总线数 30、breakout 数 2、任一接口在 link 表出现 ≤1 次。属性测试(Hypothesis):随机型号/台数/参数下,engine 输出要么 error 要么满足 —— 无端口复用、速率全匹配、breakout 子口必有已拆父口、capacity_precheck 通过的从不中途失败。roundtrip 测试见 §7。

---
附:与上一版 plan 的差异 —— 数据库验证期定为 SQLite(§4.1 约束保证可切 PG);新增 project 包与 .fabproj.json 格式(§7);程序数量、文件清单、函数签名、施工顺序全部细化到可直接执行。
