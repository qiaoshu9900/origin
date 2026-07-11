# netval 网络变更验证框架 — 工程规格书 v3.4（交付低成本 AI 施工用）

> 本文档是施工图，不是建议书。实现者必须照抄本文档的文件结构、表结构、函数签名、常量名；每个施工步骤末尾附验收命令，验收不过不得进入下一步；任何偏离需先说明理由并获批准。行为基准：`prototype/` 目录下的 v0.2 原型与 `prototype/frontend-demo.jsx` 前端示范（随附交付物）。扩展场景（新厂商 / 新命令 / 新族 / 新字段）必须严格按 §6 的四个配方施工，配方之外的文件一律不许改动。
>
> v3.1 相对 v3.0 的变更：对比单元由"族"细化为"命令实例"（§7.5，原则 1 同步修订）；新增自由配对对比（§7.6、§9 adhoc 接口）；新增读时属性忽略（§7.7、findings 接口 ignore_fields 参数）；Finding 增加 instance 字段；reader 支持实例作用域取数。
>
> v3.2 相对 v3.1 的变更：解析层与对比层改为"目录即结构"——`parsers/<平台>/<族>.py` 每平台一个文件夹、每族一个文件；`compare/families/<族>.py` 每族一个对比器文件，键对齐算法唯一实现在 engine.keyed_diff、各族文件只做前后处理并委托（§5.3、§5.7）；新增归一化契约测试（同族跨平台记录字段集必须一致，跨设备/跨平台 adhoc 对比因此天然可行）；配方 A/B 文件清单同步修订。
>
> v3.3 相对 v3.2 的变更：**富化物化为派生快照**——取消对比时的临时富化（原 §7.3），改为显式动作 `derive/enrich`：以 `(afi_safi, vrf, rd, prefix, nexthop)` 匹配 detail 路径，生成 kind='enriched' 的派生快照（§7.3 重写、§4.2 snapshot 加列、新增 §5.9 derive 模块）；bgp_prefix_detail 的对比单元改为族级聚合（FamilySpec.instance_scope，同设备全部 detail 命令合为一个单元，§7.5）；enriched 与未 enriched 同族可比，服务端以 suggested_ignore_fields 预选忽略被填充字段（§7.8）；前端阶段轨道调序为 设备→PRE→POST→DETAIL(清单+导入)→对比→导出（§11）；ENGINE_RULES_VERSION 递增至 "3.3"。
>
> v3.4 相对 v3.3 的变更：**对比结果物化为不可变运行工件**（原则 2 重写）——每次对比产出一行 `compare_run` 登记（§4.2 新表）+ 一个写一次永不改的 `findings JSONL.gz` 工件文件（§5.8 重写）；findings 接口、html/csv/xlsx 导出、bundle.json 全部以该工件为唯一数据源（时序 B/C 重写）；对比改为异步执行（POST 返回 running，轮询 compare_run.status，无需消息队列——进程内线程池）；进程内缓存降级为工件的 LRU 装载器；项目删除级联清理 compare_run 行与工件文件；工件是纯函数的 memoization——同参数重算必须与工件逐字节一致（S6 验收含 --verify）。

---

## 0. 硬性原则（违反即返工）

1. **对比是对快照数据库的运算，别无其他输入；对比的最小单元是命令实例**。`compare/` 包函数的入参只允许是"从六张宽表与 coverage 表 SELECT 出来的记录字典列表"；签名中禁止出现文件路径、原始文本、HTTP 对象。对齐与比较按 `(device, family, params)` 命令实例逐个进行（§7.5）——不同实例的记录永不混入同一次键对齐，即使它们同族；唯一例外是 `instance_scope='family'` 的族（当前仅 bgp_prefix_detail）按族级聚合为一个单元（§7.5）。对比引擎内不做任何数据加工（富化是显式的派生动作，见 §7.3）。缓存失效后的重算 = 重新 SELECT + 重新计算，输出与首次逐字节一致（同一引擎版本下）。
2. **对比结果是不可变运行工件，不是可变状态**。每次对比落一行 `compare_run` 登记 + 一个 `findings JSONL.gz` 工件文件（写一次，永不 UPDATE/追加）。工件是纯函数的 memoization：同 `(before, after, rules_version)` 重算必须与工件逐字节一致。findings 永不进关系宽表；findings 接口与全部导出物（html/csv/xlsx/bundle.json）以工件为唯一数据源。
3. **程序不做重要性判断**。Finding 没有 severity、没有原因推断。分析属于 §10 的 AI 接入点（V2），且 AI 分析模块只许消费 bundle.json 契约，不许 import compare 内部。
4. **`compare/`、`detailplan/policy.py`、`spec/` 是纯层**：禁止 import sqlalchemy / fastapi / 任何 IO。
5. **分层单向**：`router → service → (compare | ingest | store/repo) → db`。compare 不得调用 store。
6. **原始 CLI 文本不进数据库**；可选 gzip 归档文件系统（唯一用途：解析器修复后重放）。
7. **删除项目 = 单事务级联清空其全部数据**。数据库常态只装进行中的项目。
8. **数据库可移植**：列类型只用 TEXT / INTEGER / REAL / JSON；无外键；宽表无主键；切库 = 改 `DATABASE_URL`。
9. **扩展只走注册表**：新厂商/新命令/新族按 §6 配方施工；配方未列出的文件出现在 diff 里即返工。
10. 不引入本文档之外的服务与依赖（无 Redis / Celery / 消息队列 / 第二数据库 / UI 组件库）。

## 1. 程序清单（3 个可运行程序）

| # | 程序 | 技术（版本锁定在 pyproject / package.json） | 进程形态 |
|---|---|---|---|
| P1 | backend | Python 3.12 · FastAPI · SQLAlchemy 2 · Pydantic v2 · Alembic · openpyxl · ntc-templates+textfsm | `uvicorn app.main:app` |
| P2 | frontend | Node 20 · Vite · React 18 · TS · TanStack Query/Table/Virtual · Zustand · lucide-react | dev `vite`，生产 nginx |
| P3 | cli | `python -m app.cli`，复用 P1 全部包 | ingest / compare / export / gen-detail |

数据库：验证期 `sqlite:///data/netval.db`；生产 PostgreSQL 16。

## 2. 仓库结构（文件级；每文件一行职责；★=纯函数文件）

```
netval/
├── docker-compose.yml / Makefile        # make dev|test|migrate|export-openapi|baseline
├── prototype/                           # v0.2 原型 + frontend-demo.jsx(只读,行为与视觉基准)
├── backend/
│   ├── pyproject.toml / alembic/
│   └── app/
│       ├── main.py                      # FastAPI 实例、挂 routers、异常处理器
│       ├── config.py                    # Settings: DATABASE_URL, RAW_ARCHIVE_DIR, COMPARE_ARTIFACT_DIR
│       ├── db.py                        # engine/session 工厂
│       ├── version.py                   # ENGINE_RULES_VERSION="3.3" · BUNDLE_SCHEMA_VERSION=1
│       ├── spec/
│       │   ├── families.py            ★ # FAMILIES 注册表(§5.1) —— 配方 B/D 改这里
│       │   ├── commands.py            ★ # COMMAND_ROUTES 路由表(§5.2) —— 配方 A/B/C 改这里
│       │   └── normalize.py           ★ # normalize_command / canonical_params / scalarize
│       ├── ingest/
│       │   ├── segment.py             ★ # marker 切分(语义与原型 segment.py 一致)
│       │   ├── parsers/                 # ── 目录即结构:平台一文件夹,族一文件 ──
│       │   │   ├── registry.py          # 约定式发现:扫描 <平台>/<族>.py 的 parse() 建 PARSERS(§5.3)
│       │   │   ├── contract.py        ★ # record_contract(family) 字段集校验(§5.3)
│       │   │   ├── arista_eos/
│       │   │   │   ├── _access.py     ★ # eAPI JSON 字段访问器(平台内共用;真机字段出入只改这里)
│       │   │   │   ├── route_table.py ★ # def parse(raw, params) -> list[dict]
│       │   │   │   ├── forwarding_table.py ★
│       │   │   │   ├── bgp_paths.py   ★
│       │   │   │   ├── bgp_neighbor_routes.py ★  # received/advertised 输出同构,共用一文件
│       │   │   │   └── bgp_prefix_detail.py ★
│       │   │   └── cisco_xr/
│       │   │       ├── _textfsm.py    ★ # 模板加载助手(ntc-templates 优先,templates/xr 兜底)
│       │   │       ├── route_table.py ★
│       │   │       ├── forwarding_table.py ★    # show cef 正则
│       │   │       ├── bgp_paths.py   ★
│       │   │       ├── bgp_neighbor_routes.py ★
│       │   │       └── bgp_prefix_detail.py ★
│       │   ├── templates/xr/            # 自写 TextFSM 模板(ntc 缺口时);配方 A 建 templates/<平台>/
│       │   └── service.py               # IngestService(§5.4):切分→路由→解析→写库,事务边界
│       ├── project/
│       │   ├── models.py                # ORM: Project, ProjectDevice, Snapshot, DetailPlan
│       │   ├── schemas.py / repo.py     # repo 含 delete_project_cascade(§3-D)
│       │   ├── service.py / router.py   # /projects/*
│       ├── store/
│       │   ├── models.py                # 六张宽表 ORM + FAMILY_TABLE 映射 —— 配方 B 改这里
│       │   ├── writer.py                # write_records / write_coverage(§5.5)
│       │   └── reader.py                # fetch_records / fetch_coverage / fetch_instances(§5.5)
│       ├── compare/                     # ── 对比层同构:算法一处,族一文件;引擎内零数据加工 ──
│       │   ├── types.py               ★ # Finding / CompareSummary(§5.6)
│       │   ├── coverage.py            ★ # coverage_findings(§7.1)
│       │   ├── engine.py              ★ # keyed_diff:键对齐算法的唯一实现(§5.7)
│       │   ├── registry.py              # 约定式发现:扫描 families/<族>.py 的 compare() 建 COMPARATORS
│       │   └── families/              ★ # 每族一个对比器文件:该族对比行为的唯一维护面
│       │       ├── route_table.py       #   默认形态:直接委托 keyed_diff
│       │       ├── forwarding_table.py
│       │       ├── bgp_paths.py         #   + add-path 同键并入 nexthop 的前处理(§7.2)
│       │       ├── bgp_neighbor_received.py    # 默认形态(富化已物化,对比器不再加工数据)
│       │       ├── bgp_neighbor_advertised.py
│       │       └── bgp_prefix_detail.py # instance_scope='family':族级聚合单元(§7.5)
│       ├── derive/                      # ── 派生快照:显式富化动作(§5.9/§7.3)──
│       │   ├── enrich.py              ★ # match_detail:纯函数,(记录,detail)→(填充后记录,统计)
│       │   ├── service.py               # run_enrich:读源快照→匹配→建 kind='enriched' 新快照落库
│       │   └── router.py                # POST /snapshots/{sid}/derive/enrich
│       ├── compare_svc/
│       │   ├── artifact.py              # 运行工件:JSONL.gz 原子写/流读/LRU 装载器(§5.8)
│       │   ├── service.py               # submit_compare(异步)/get_run/get_findings/verify
│       │   └── router.py                # /projects/{id}/compares · /compares/{cid}/*
│       ├── detailplan/
│       │   ├── policy.py              ★ # select_prefixes(§8)
│       │   ├── render.py              ★ # 前缀清单→各平台命令文本
│       │   ├── service.py / router.py
│       ├── export/
│       │   ├── html.py / tabular.py   ★ # 三种人读导出(移植原型,去 severity)
│       │   ├── bundle.py              ★ # render_bundle_json —— AI 输入契约(§10)
│       │   └── router.py
│       └── tests/
│           ├── fixtures/                # eos/ xr/ 采集样例文本(含 vpnv4、cef、add-path)
│           ├── baselines/               # 基准 JSON:各样例的期望行数与期望事实集
│           ├── test_normalize.py test_routing.py test_parsers_eos.py test_parsers_xr.py
│           ├── test_record_contract.py  # 每 parser 的 fixture 输出过 record_contract(§5.3)
│           ├── test_registry_completeness.py  # 路由表×解析器×对比器三方对账(§5.3/§5.7)
│           ├── test_cross_platform.py   # 同族 EOS/XR 记录字段集一致;跨平台 adhoc 冒烟(§7.6)
│           ├── test_compare_engine.py test_enrich.py test_coverage.py
│           ├── test_seed_replay.py      # 事实集与 baselines 深度相等(§12-S5)
│           ├── test_detailplan.py test_exports.py test_bundle_schema.py
│           ├── test_project_lifecycle.py test_api_flows.py
│           └── test_layering.py         # 静态检查:compare/spec/policy 无违规 import(§12-S2)
└── frontend/src/                        # 结构照 prototype/frontend-demo.jsx 的组件划分(§11)
```

## 3. 数据流与时序（必须按此实现）

```
A. 上传:POST /snapshots/{sid}/captures(multipart)
   IngestService.ingest_files: 对每文件 segment.parse_capture_text
     → 逐命令 commands.route_command(platform, cmd) → RoutedCommand|None
     → None: 只写 coverage(family='unknown', parse_status='unparsed')
     → 有 family: registry.get_parser(platform, family)
        无 parser → coverage(parse_status='unparsed')
        有 parser → try records=parser(raw, params)
                    成功→ writer.write_records + coverage('ok')
                    异常→ coverage('error'),宽表不写,继续下一命令
     全文件一个事务;可选 gzip 归档 RAW_ARCHIVE_DIR/{project}/{sid}/{device}/
   返回 IngestSummary(devices, commands, records, unparsed:[{device,command,reason}])

B. 对比(异步):POST /projects/{p}/compares {before_sid, after_sid}
   立即:INSERT compare_run(status='running', kind='auto', 参数, rules_version) → 返回 {compare_id, status}
   后台(进程内 ThreadPoolExecutor,max_workers=1,无消息队列):
     cov_b, cov_a = reader.fetch_coverage(×2)                    # ← 只从库读
     任一侧 kind=='enriched' → 对比范围收窄到其 derived_meta.family(§7.8),
       其余族不产生 missing_command 噪音;suggested_ignore_fields 写入登记行
     findings = compare.coverage.coverage_findings(cov_b, cov_a)
     paired = 两侧 parse_status==ok 且 (device,family,params) 相等的实例交集;
       instance_scope=='family' 的族改按 (device,family) 聚合配对,instance 标签 'all'(§7.5)
     for inst in paired(按 device, family, params 排序保证确定性):
       b = reader.fetch_records(before, inst.device, inst.family, scope=inst.scope)
       a = reader.fetch_records(after,  inst.device, inst.family, scope=inst.scope)
       findings += registry.compare_family(inst.device, inst.family, b, a, instance=inst.label)
       # 逐实例取数逐实例释放:峰值内存 = 最大单实例,不是整快照
     artifact.write(compare_id, findings)        # JSONL.gz,写一次;summary 一并算出
     UPDATE compare_run SET status='done', summary=…, artifact_path=…, finding_count=…
     (异常→ status='failed', error 写登记行;工件不落半成品)
   GET /compares/{cid} → {status, summary?, rules_version, suggested_ignore_fields?}(前端轮询)
   GET /compares/{cid}/findings?…&instance=&ignore_fields=&cursor=&limit=
     ArtifactLoader(进程 LRU)装载工件→内存过滤分页;重启后工件仍在,零重算

B'. 自由配对:POST /projects/{p}/compares/adhoc {a:{…}, b:{…}}
   同 B:登记行 kind='adhoc'(参数存 payload JSON)→ 后台计算 → 工件
   对齐键 = spec.identity 去掉"a/b 参数值不同的键"(§7.6);登记行含 align_dropped

C. 导出:GET /compares/{cid}/export.(html|csv|xlsx)  与  GET /compares/{cid}/bundle.json
   四种渲染器共用同一数据源:compare_run 登记行(meta/summary) + 工件(findings)
   bundle.json ≈ 工件的流式返回 + meta 头;html = 自包含渲染壳 + 内嵌工件数据

D. 删除:DELETE /projects/{p}
   repo.delete_project_cascade:单事务
     for sid in project 的全部 snapshot ids(含 kind='enriched'): DELETE 六宽表+coverage
     DELETE compare_run(本项目全部) / detail_plan / snapshot / project_device / project
   事务提交后删除工件文件目录 data/compares/{project_id}/(文件删除失败仅告警,不回滚)

E. 派生(显式富化):POST /snapshots/{sid}/derive/enrich {family:'bgp_paths'|'bgp_neighbor_received'}
   DeriveService.run_enrich:
     rows   = reader.fetch_records(sid, 每设备, family)          # 源快照该族全量
     detail = reader.fetch_records(sid, 每设备, 'bgp_prefix_detail')
     enriched, stats = derive.enrich.match_detail(rows, detail)  # 纯函数,§5.9
     新建 snapshot(kind='enriched', source_snapshot_id=sid,
                   derived_meta={family, match_key, fields_filled, rows_total,
                                 rows_matched, ambiguous})
     写入:enriched 记录(挂新 snapshot_id) + 复制源快照该族的 coverage 行(实例配对由此成立)
   返回 {snapshot_id, rows_matched, rows_total, fields_filled}
   派生快照出现在快照列表,可单独删除,项目删除时随项目级联(时序 D)
```

## 4. 数据层

### 4.1 硬约束
同 v2：`TEXT/INTEGER/REAL/JSON` 之外的列类型禁止；无外键；宽表无主键；多值字段（多下一跳/community/标签栈）经 `scalarize` 排序拼接为单 TEXT；Alembic 自 S2 启用。

### 4.2 DDL（照抄；索引名与列序不得改动）

```sql
project          (id INTEGER PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
                  note TEXT DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
project_device   (project_id INTEGER NOT NULL, device TEXT NOT NULL, platform TEXT NOT NULL);
snapshot         (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, label TEXT NOT NULL,
                  kind TEXT NOT NULL,            -- 'pre'|'post'|'adhoc'|'enriched'
                  source_snapshot_id INTEGER,    -- 仅 kind='enriched':派生自哪个快照
                  derived_meta JSON,             -- 仅 kind='enriched':{family, match_key,
                                                 --   fields_filled, rows_total, rows_matched, ambiguous}
                  taken_at TEXT NOT NULL);
detail_plan      (project_id INTEGER NOT NULL, device TEXT NOT NULL, afi_safi TEXT NOT NULL,
                  vrf TEXT NOT NULL DEFAULT '', rd TEXT NOT NULL DEFAULT '', prefix TEXT NOT NULL);

-- 对比运行登记:一次对比一行;findings 本体在工件文件里,永不进关系表(原则 2)
compare_run      (compare_id TEXT PRIMARY KEY,          -- base64(参数+rules_version),自描述
                  project_id INTEGER NOT NULL,
                  kind TEXT NOT NULL,                   -- 'auto'|'adhoc'
                  payload JSON NOT NULL,                -- auto:{before_sid,after_sid} adhoc:{a,b}
                  rules_version TEXT NOT NULL,
                  status TEXT NOT NULL,                 -- 'running'|'done'|'failed'
                  summary JSON,                         -- done 后:计数摘要
                  suggested_ignore_fields JSON,         -- §7.8
                  align_dropped JSON,                   -- adhoc:§7.6
                  artifact_path TEXT,                   -- data/compares/{project_id}/{compare_id}.jsonl.gz
                  finding_count INTEGER,
                  error TEXT,
                  created_at TEXT NOT NULL, finished_at TEXT);
CREATE INDEX ix_run ON compare_run(project_id, created_at);

command_coverage (snapshot_id INTEGER NOT NULL, device TEXT NOT NULL, platform TEXT NOT NULL,
                  family TEXT NOT NULL, params TEXT NOT NULL, command TEXT NOT NULL,
                  record_count INTEGER NOT NULL, parse_status TEXT NOT NULL);
CREATE INDEX ix_cov ON command_coverage(snapshot_id, device, family);

route_table      (snapshot_id INTEGER NOT NULL, device TEXT NOT NULL,
                  vrf TEXT NOT NULL, prefix TEXT NOT NULL,
                  protocol TEXT, preference INTEGER, metric INTEGER, nexthops TEXT);
CREATE INDEX ix_rt ON route_table(snapshot_id, device, vrf, prefix);

forwarding_table (snapshot_id INTEGER NOT NULL, device TEXT NOT NULL,
                  vrf TEXT NOT NULL, prefix TEXT NOT NULL,
                  nexthops TEXT, labels TEXT NOT NULL DEFAULT '');
CREATE INDEX ix_fib ON forwarding_table(snapshot_id, device, vrf, prefix);

bgp_paths        (snapshot_id INTEGER NOT NULL, device TEXT NOT NULL,
                  afi_safi TEXT NOT NULL, vrf TEXT NOT NULL DEFAULT '', rd TEXT NOT NULL DEFAULT '',
                  prefix TEXT NOT NULL, peer TEXT NOT NULL DEFAULT '', nexthop TEXT,
                  aspath TEXT, med INTEGER, localpref INTEGER, origin TEXT,
                  communities TEXT NOT NULL DEFAULT '', best INTEGER, valid INTEGER);
CREATE INDEX ix_bgp ON bgp_paths(snapshot_id, device, afi_safi, vrf, rd, prefix, peer);

bgp_neighbor_routes (snapshot_id INTEGER NOT NULL, device TEXT NOT NULL,
                  afi_safi TEXT NOT NULL, vrf TEXT NOT NULL DEFAULT '', rd TEXT NOT NULL DEFAULT '',
                  neighbor TEXT NOT NULL, direction TEXT NOT NULL,   -- 'received'|'advertised'
                  prefix TEXT NOT NULL, nexthop TEXT, aspath TEXT, med INTEGER,
                  localpref INTEGER, origin TEXT, communities TEXT NOT NULL DEFAULT '', best INTEGER);
CREATE INDEX ix_nbr ON bgp_neighbor_routes(snapshot_id, device, direction, afi_safi, vrf, neighbor, prefix);

bgp_prefix_detail (snapshot_id INTEGER NOT NULL, device TEXT NOT NULL,
                  afi_safi TEXT NOT NULL, vrf TEXT NOT NULL DEFAULT '', rd TEXT NOT NULL DEFAULT '',
                  prefix TEXT NOT NULL, peer TEXT NOT NULL DEFAULT '', nexthop TEXT,
                  aspath TEXT, med INTEGER, localpref INTEGER, origin TEXT,
                  communities TEXT NOT NULL DEFAULT '', best INTEGER, valid INTEGER,
                  labels TEXT NOT NULL DEFAULT '');
CREATE INDEX ix_pfx ON bgp_prefix_detail(snapshot_id, device, afi_safi, vrf, rd, prefix, peer);
```

空值规约（引擎正确性依赖，必须一致）：**身份键列一律 NOT NULL，取不到用空串 `''`**；比较字段可 NULL，引擎中 `None ≡ ''`。

## 5. 函数签名（必须照抄；类型注解不可省略）

### 5.1 spec/families.py
```python
@dataclass(frozen=True)
class FamilySpec:
    name: str                      # == 注册键
    table: str                     # 宽表名
    identity: tuple[str, ...]      # 身份键列,顺序即对齐键顺序
    compare: tuple[str, ...]       # 比较字段
    ignore: tuple[str, ...] = ()
    enrichment_source: bool = False
    direction_const: str | None = None    # bgp_neighbor_routes 用:'received'|'advertised'
    instance_scope: str = "command"       # 'command'=按命令实例 | 'family'=同设备聚合为一个单元(§7.5)
    enrich_target: bool = False           # 可作为 derive/enrich 的目标族(§7.3)

FAMILIES: dict[str, FamilySpec] = {
  "route_table":            FamilySpec("route_table","route_table",("vrf","prefix"),
                              ("protocol","nexthops","preference","metric")),
  "forwarding_table":       FamilySpec("forwarding_table","forwarding_table",("vrf","prefix"),
                              ("nexthops","labels")),
  "bgp_paths":              FamilySpec("bgp_paths","bgp_paths",
                              ("afi_safi","vrf","rd","prefix","peer"),
                              ("nexthop","aspath","med","localpref","origin","communities","best","valid"),
                              enrich_target=True),
  "bgp_neighbor_received":  FamilySpec("bgp_neighbor_received","bgp_neighbor_routes",
                              ("afi_safi","vrf","rd","neighbor","prefix"),
                              ("nexthop","aspath","med","localpref","origin","communities","best"),
                              direction_const="received", enrich_target=True),
  "bgp_neighbor_advertised":FamilySpec("bgp_neighbor_advertised","bgp_neighbor_routes",
                              ("afi_safi","vrf","rd","neighbor","prefix"),
                              ("nexthop","aspath","med","localpref","origin","communities","best"),
                              direction_const="advertised"),
  "bgp_prefix_detail":      FamilySpec("bgp_prefix_detail","bgp_prefix_detail",
                              ("afi_safi","vrf","rd","prefix","peer"),
                              ("nexthop","aspath","med","localpref","origin","communities","best","valid","labels"),
                              enrichment_source=True, instance_scope="family"),
}
```

### 5.2 spec/commands.py 与 normalize.py
```python
@dataclass(frozen=True)
class CommandRoute:
    platform: str                  # 'arista_eos' | 'cisco_xr' | 配方 A 新增值
    pattern: re.Pattern            # 匹配归一化后的命令
    family: str                    # FAMILIES 的键
    afi_safi: str                  # 'ipv4_unicast'|'vpnv4_unicast'|''(非BGP族)
    groups: dict[int, str]         # 正则组号 → 参数名('vrf'|'neighbor'|'prefix'|'rd')

COMMAND_ROUTES: list[CommandRoute]   # 顺序=优先级,特异性高者在前(§5.2.1 现行清单)

@dataclass(frozen=True)
class RoutedCommand:
    family: str; params: dict[str, str]; afi_safi: str; wants_json: bool

def route_command(platform: str, command: str) -> RoutedCommand | None
def normalize_command(cmd: str) -> tuple[str, bool]        # (归一化串, wants_json)
def canonical_params(params: dict[str, str]) -> str        # 键字母序;'k=v' 分号连接
def scalarize(values: Iterable[str]) -> str                # sorted + ' '.join,去空
```
参数缺省规约：ipv4 族 vrf 缺省 `default`；vpnv4 全局视图 `vrf=''`；rd 无则 `''`；params 必含 `afi_safi`。

**5.2.1 现行命令清单**（正则按此语义实现；EOS 均带 `| json`）：

| family(+afi) | arista_eos | cisco_xr |
|---|---|---|
| route_table | `show ip route [vrf X]` | `show route [vrf X] [ipv4]` |
| forwarding_table | 占位注册 `show fib route …`（实测定稿前 parser 缺省→unparsed，链路不断） | `show cef [vrf X] ipv4` |
| bgp_paths·ipv4 | `show ip bgp [vrf X]` | `show bgp [vrf X] ipv4 unicast` |
| bgp_paths·vpnv4 | `show bgp vpn-ipv4`（同上占位策略） | `show bgp vpnv4 unicast [rd R] [vrf X]` |
| received/advertised·ipv4 | `show ip bgp neighbors N (routes\|advertised-routes) [vrf X]` | `show bgp [vrf X] ipv4 unicast neighbors N (routes\|advertised-routes)` |
| received/advertised·vpnv4 | —（版本确认后加，配方 C） | `show bgp vpnv4 unicast neighbors N (routes\|advertised-routes)` |
| bgp_prefix_detail·ipv4 | `show ip bgp P [vrf X]` | `show bgp [vrf X] ipv4 unicast P` |
| bgp_prefix_detail·vpnv4 | — | `show bgp vpnv4 unicast rd R P` |

### 5.3 解析器契约（目录即结构）

文件布局约定：`ingest/parsers/<platform>/<family>.py`，每文件导出唯一入口：
```python
def parse(raw_text: str, params: dict[str, str]) -> list[dict]
```
received/advertised 输出同构，共用 `bgp_neighbor_routes.py`（registry 将其同时注册到两个族）。平台内共用的字段访问器/模板助手放该平台目录下的 `_` 前缀私有模块；**平台目录之间禁止互相 import**（test_layering 检查）——跨平台可共用的逻辑只能上提到 contract.py 或 spec 层。

```python
# ingest/parsers/registry.py —— 约定式发现,禁止手工维护映射 dict
def discover() -> dict[tuple[str, str], Parser]
# 扫描 parsers/ 下的平台目录:模块名(去 .py)即 family 名,导出的 parse 即解析器;
# bgp_neighbor_routes.py 特例注册为 received+advertised 两个键
PARSERS = discover()
def get_parser(platform: str, family: str) -> Parser | None
ALLOWED_UNPARSED: set[tuple[str, str]]   # 已知占位:如 ("arista_eos","forwarding_table")
# test_registry_completeness 三方对账:COMMAND_ROUTES 中出现的每个 (platform,family)
# 必须 ∈ PARSERS ∪ ALLOWED_UNPARSED;PARSERS 中不得有路由表不认识的键(死代码)

# ingest/parsers/contract.py —— 归一化契约(跨平台同族格式一致的强制手段)
def record_contract(family: str) -> frozenset[str]   # = FamilySpec.identity ∪ compare
def validate_records(family: str, records: list[dict]) -> list[str]   # 违规描述,空=合规
# 规则:record 键集 ⊆ contract;身份键必在且非 None;多值字段已 scalarize
# test_record_contract:每平台每族 fixture 解析输出全部过 validate_records
# test_cross_platform:同族的 EOS 与 XR fixture 输出,字段键集完全一致
# ——契约达标的直接效果:同族记录跨平台/跨设备可直接进 keyed_diff(§7.6 adhoc 因此天然可行)
```
记录规约：键与宽表列同名；身份键字段必在且非 None（空用 `''`）；多值字段已 `scalarize`；`snapshot_id/device/direction` 由 writer 补，解析器不产出。解析器 raise 任何异常都由 IngestService 捕获为 `error`。

### 5.4–5.5 ingest 与 store
```python
class IngestService:
    def ingest_files(self, snapshot_id: int, files: list[tuple[str, bytes]]) -> IngestSummary
@dataclass
class IngestSummary:
    devices: int; commands: int; records: int
    unparsed: list[dict]          # {device, command, reason:'unknown_command'|'no_parser'|'parse_error:<msg>'}

# store/writer.py
def write_records(session, snapshot_id: int, device: str, family: str, records: list[dict]) -> int
def write_coverage(session, snapshot_id: int, device: str, platform: str,
                   family: str, params: str, command: str, record_count: int, parse_status: str) -> None
# store/reader.py —— compare 的唯一数据来源(原则 1)
def fetch_records(session, snapshot_id: int, device: str, family: str,
                  scope: dict[str, str] | None = None) -> list[dict]
# scope=实例参数 dict;其中能映射到该宽表列名的键(afi_safi/vrf/rd/neighbor/prefix)
# 逐一转为 WHERE col=val;不能映射的键忽略。scope=None → 设备级全取(仅富化取 detail 时用)
def fetch_coverage(session, snapshot_id: int) -> list[dict]
def fetch_instances(session, snapshot_id: int, device: str | None = None,
                    family: str | None = None) -> list[dict]
# coverage 中 parse_status=='ok' 的行反解 params → 实例清单
# [{device, family, params:dict, params_str, record_count}];供配对循环与前端实例选择器
def devices_of(session, snapshot_id: int) -> list[str]
```
`write_records` / `fetch_records` 经 `store.models.FAMILY_TABLE: dict[family, (Table, direction_const)]` 分发；received/advertised 写读同表带 direction 条件。

### 5.6–5.7 compare 包（算法一处，族一文件）
```python
Change = Literal["added","removed","changed","missing_command","unparsed","duplicate_path_key"]
@dataclass(frozen=True)
class Finding:
    device: str; family: str; change: Change
    instance: str                               # 所属命令实例的 params_str;coverage 事实同
    identity: dict[str, str]                    # 身份键名→值(自由配对时不含被剔除的键)
    fields_changed: tuple[str, ...] = ()
    before: dict | None = None; after: dict | None = None

# compare/engine.py —— 键对齐算法的唯一实现;families/*.py 内禁止重写此逻辑
def keyed_diff(device: str, spec: FamilySpec,
               before: list[dict], after: list[dict],
               instance: str = "",
               identity: tuple[str, ...] | None = None) -> list[Finding]
# identity=None → 用 spec.identity;自由配对传"剔除差异键后的对齐键"(§7.6)
# 语义:①键化(identity 顺序取值,None→'');②同键多行→并入 nexthop 为附加键成分,
#   仍冲突则保留首行并对该键产出一条 duplicate_path_key(before/after 各判);
#   ③仅前→removed(before=比较字段全量);仅后→added(after=全量);
#   ④两侧→逐 compare 字段找差(None≡''),有差→changed(before/after 只含差异字段)

# compare/families/<family>.py —— 每族一文件,导出唯一入口;只许前/后处理并委托 keyed_diff
def compare(device: str, before: list[dict], after: list[dict],
            instance: str = "", identity: tuple[str, ...] | None = None) -> list[Finding]
# 默认形态(route_table.py / bgp_neighbor_received.py 等):
#   SPEC = FAMILIES["route_table"]
#   def compare(...): return keyed_diff(device, SPEC, before, after, instance, identity)
# bgp_paths.py:add-path 前处理(§7.2)再委托
# received 不再有富化前处理——富化已物化为派生快照(§7.3),对比器比的就是库里躺着的

# compare/registry.py —— 约定式发现,与 parsers 同构
COMPARATORS: dict[str, CompareFn] = discover()   # 扫描 families/<family>.py 的 compare
def compare_family(device, family, before, after, instance="", identity=None)
# 服务层唯一入口:查 COMPARATORS 分发
# test_registry_completeness:FAMILIES 中每族(含 bgp_prefix_detail,双角色)必有对比器文件;
#   COMPARATORS 不得含 FAMILIES 之外的键

def coverage_findings(cov_before: list[dict], cov_after: list[dict])
        -> tuple[list[Finding], set[tuple]]     # (事实, 单侧缺失的 (device,family,params) 集)
```

### 5.9 derive 包（显式富化，纯函数 + 落库编排）
```python
# derive/enrich.py —— 纯函数(禁止 IO)
ENRICH_FIELDS = ("communities","localpref","med","origin","aspath")   # 只填这些,补空不覆盖
@dataclass(frozen=True)
class EnrichStats:
    rows_total: int; rows_matched: int; ambiguous: int; fields_filled: tuple[str, ...]
def match_detail(rows: list[dict], detail: list[dict],
                 row_peer_key: str) -> tuple[list[dict], EnrichStats]
# 匹配键 (afi_safi, vrf, rd, prefix, nexthop) —— detail 中一个 prefix 的 N 个 nexthop
#   即 N 条路径,各自 match 到 rows 中相同键的行
# 多候选兜底:同键多条 detail 路径时,优先 detail.peer == row[row_peer_key]
#   (bgp_paths→'peer',received→'neighbor');仍多条→按 detail 记录确定性排序取首,ambiguous+=1
# 填充:仅当 row 字段为 None/'' 时取 detail 值;fields_filled=实际填过值的字段集合

# derive/service.py
def run_enrich(session, snapshot_id: int, family: str) -> dict
# 校验 FAMILIES[family].enrich_target;流程见时序 E;同一源可多次派生(各成新快照,旧的手动删)
# → {snapshot_id, rows_total, rows_matched, ambiguous, fields_filled}
```

### 5.8 compare_svc 与 export（工件为唯一数据源）
```python
# compare_svc/artifact.py —— 运行工件:JSONL.gz,一行一个 Finding(json),写一次永不改
def write(compare_id: str, project_id: int, findings: Iterable[Finding]) -> tuple[str, int]
#   → (artifact_path, finding_count);写临时文件后原子 rename,不落半成品
def stream(artifact_path: str) -> Iterator[Finding]        # 逐行流式读(导出/大结果过滤用)
class ArtifactLoader:                                       # 进程 LRU(上限 4 个工件)装载器
    def load(self, artifact_path: str) -> list[Finding]     # 全量装载供交互过滤;重启后可再装载
# 规模逃生舱(现在不实现,只留注释):工件 >10^6 条时改为"导入临时表 SQL 过滤",接口不变

# compare_svc/service.py
def submit_compare(session, project_id: int, payload: dict, kind: str) -> str
#   INSERT compare_run(status='running') → 提交进程内 ThreadPoolExecutor(max_workers=1) → compare_id
#   同参数且 status='done' 的 run 已存在 → 直接返回旧 compare_id(memo 命中,不重算)
def get_run(session, compare_id: str) -> dict               # 轮询:status/summary/…(登记行原样)
def get_findings(session, compare_id: str, f: FindingFilters, cursor: int, limit: int) -> dict
#   FindingFilters: device|family|afi_safi|vrf|change|instance|q|ignore_fields 全部可选
#   ArtifactLoader 装载 → 内存过滤分页;ignore_fields 语义见 §7.7
#   → {items:[FindingOut], next_cursor:int|null, total_filtered:int, suppressed_by_ignore:int}
def verify(session, compare_id: str) -> bool                # 重算并与工件逐字节比对(CLI --verify)

def render_html(meta: dict, findings) -> str    # 自包含:渲染壳 + 内嵌工件数据
def render_csv(findings) -> bytes               # UTF-8 BOM;列:device,family,instance,change,identity,fields_changed,before,after
def render_xlsx(findings) -> bytes              # sheet=族;首行 meta
def render_bundle_json(meta: dict, summary: dict, findings) -> dict     # §10.1;≈工件流式返回+meta 头
```

## 6. 扩展配方（唯一合法的扩展方式；改动文件超出清单即返工）

### 配方 A：新增设备平台（例：juniper_junos）
允许改动的文件：`spec/commands.py`、`ingest/parsers/juniper_junos/`（新建目录）、`ingest/templates/juniper_junos/`（新建，可选）、`tests/fixtures/junos/`、`tests/test_parsers_junos.py`（新建）、`tests/test_routing.py`（追加用例）、前端平台常量 `frontend/src/constants.ts`。**registry.py 不改**——约定式发现，建对目录文件即完成注册。
1. commands.py 追加该平台的 CommandRoute 若干（只映射到**既有族**；要新族先走配方 B）。
2. 新建目录 `parsers/juniper_junos/`，每族一个 `<family>.py` 导出 `parse(raw, params)`；平台内共用逻辑放 `_` 前缀私有模块；暂不支持的族**不建文件**并把 `("juniper_junos", 族)` 加进 ALLOWED_UNPARSED。
3. fixtures 放至少每族 1 份真机脱敏样例；test_parsers_junos.py 对每样例断言：行数、任取 2 行的全字段值。
4. test_routing.py 追加：该平台每条命令 → 期望 (family, params, afi_safi)，含 vrf 缺省与归一化（大小写/多空格）用例。
5. **完成检查单**：`pytest tests/test_routing.py tests/test_parsers_junos.py tests/test_record_contract.py tests/test_registry_completeness.py tests/test_cross_platform.py -q` 全绿（契约测试自动覆盖新平台——同族字段集必须与既有平台一致）；端到端 `python -m app.cli ingest` 该平台样例后 coverage 全 ok；`git diff --name-only` 输出 ⊆ 上述清单（尤其：compare/、store/、export/、parsers/registry.py 零改动）。

### 配方 B：新增命令族（例：ospf_neighbors）
允许改动：`spec/families.py`、`spec/commands.py`、`alembic/versions/*`（新迁移）、`store/models.py`、各平台目录下新建 `<family>.py`、`compare/families/<family>.py`（新建）、`compare_svc/service.py`（仅当需要富化编排时）、fixtures/baselines/tests、`version.py`。
1. families.py 加 FamilySpec（身份键先想 vrf/实例维度，参照 §4.2 空值规约）。
2. Alembic 迁移建宽表 + 复合索引（`(snapshot_id, device, *identity)` 打头）。
3. store/models.py 加 ORM 与 FAMILY_TABLE 映射。
4. commands.py 加各平台路由；各平台目录建 `<family>.py`（暂缺的平台进 ALLOWED_UNPARSED）。
5. 新建 `compare/families/<family>.py`——无特殊行为就是三行默认形态（委托 keyed_diff）。
6. fixtures + 解析测试 + 重放基准（`make baseline` 重生成 baselines）。
7. `ENGINE_RULES_VERSION` 递增（族集合变化 = 对比语义变化）。
8. **完成检查单**：test_registry_completeness / test_record_contract / test_seed_replay 全绿（基准已重生成并 review）；老族基准无 diff；建→删项目后新表 count=0（test_project_lifecycle 按 FAMILY_TABLE 遍历自动覆盖——实现时必须如此写）。

### 配方 C：既有族新增一种命令写法（例：EOS vpnv4 命令定稿）
允许改动：`spec/commands.py` 加 1 条 CommandRoute + `tests/test_routing.py` 加 1 条用例。若输出结构与既有 parser 不兼容，则还需按配方 A 的 2–4 步补 parser 分支。检查单：routing 测试绿；其余测试零 diff。

### 配方 D：既有族新增比较字段（例：bgp_paths 加 weight）
允许改动：Alembic 迁移（加列，默认 `''`/NULL）、store/models.py、各 parser 填值、families.py 的 compare 元组、`version.py` 递增、baselines 重生成。检查单：老快照数据（缺该列值）与新数据对比时该字段 `None≡''` 不误报——test_compare_engine 加一条向后兼容用例。

## 7. 对比引擎语义细则

**7.1 覆盖率**：对齐键 `(device, family, params)`。单侧缺失→`missing_command`（identity={command, params}，before/after 标 present yes/no）；双侧在但任一 parse_status≠ok→`unparsed`。coverage 事实不抑制记录级对比（§3-B 注）。instance_scope='family' 的族：missing_command 仍按单命令产出（事实照报），但对比单元不受单命令缺失影响（用两侧并集，§7.5）。
**7.2 键对齐**：见 §5.7 注释，实现必须与注释逐条一致。
**7.3 富化 = 显式派生动作（v3.3 起，取代对比时富化）**：富化不再发生在对比过程中，而是快照页/CLI 上的显式动作 `derive/enrich`（时序 E、§5.9）：以 `(afi_safi, vrf, rd, prefix, nexthop)` 为匹配键，把同快照 bgp_prefix_detail 的路径属性（ENRICH_FIELDS，补空不覆盖）填进 bgp_paths 或 bgp_neighbor_received 的记录，产出 **kind='enriched' 的派生快照**——记录源快照、匹配键、fields_filled、命中统计与歧义计数，完全可审计。detail 里一个 prefix 的 N 个 nexthop 即 N 条路径，各自命中目标族中相同 prefix+nexthop 的行；同键多候选时优先 detail.peer 与目标行 peer/neighbor 相同者，否则确定性取首并计入 ambiguous。detail 未覆盖的行原样进入派生快照、零告警。派生快照与普通快照在对比、adhoc、导出中完全同权。
**7.4 版本化**：RULES_VERSION 进 compare 响应、四种导出物 meta、compare_id。ignore_fields 是读时过滤（§7.7），不改变引擎语义，不触发版本递增。

**7.5 实例作用域（对比的最小单元）**：`instance_scope='command'`（默认）：同族的不同命令实例（`nei x.x.x.x routes` 与 `nei y.y.y.y routes`）各自独立对齐、独立比较，记录经 `fetch_records(scope=实例参数)` 按列过滤取出，Finding 带 instance 标签。这保证：① 实例间永不串行——某邻居 post 零路由时，其全部 removed 事实干净地挂在该实例名下，与其他邻居无涉；② 互相包含的采集（如全 RD 视图与单 RD 视图并存）各比各的，同一行可能出现在两个实例中——这是采集计划设计问题，引擎照实呈现、coverage 可见，不做静默去重。`instance_scope='family'`（当前仅 bgp_prefix_detail）：detail 采集本来就是"很多条命令一个文件"的一次性清单扫描，逐前缀拆成几百个实例毫无意义——同设备同快照的全部 detail 记录聚合为**一个**对比单元（instance 标签 'all'，records 取设备级全量），身份键中的 prefix+peer 保证聚合后对齐依然精确；pre 128 条命令、post 127 条时照常对比并集，缺的那条另有 missing_command 事实提示。

**7.6 自由配对（adhoc）**：任选**同族**两个实例 A、B（可跨快照、可同一快照、可跨设备）进行对比。对齐键 = `spec.identity` 去掉"A/B 实例参数中值不同的键"——比较 nei x 与 nei y 时 neighbor 被剔除，按 (afi_safi, vrf, rd, prefix) 对齐，neighbor 成为对比的轴；比较 detail 前缀 P1 与 P2 时 prefix 被剔除，按 peer 对齐。device 不同同样允许（跨设备视角对比），Finding.device 记为 `"devA⇄devB"`。响应必含 `align_dropped` 列表，前端必须明示"已按 … 对齐、… 为对比轴"。引擎复用 `compare_family(identity=对齐键)`，无任何专用比较代码。

**7.7 属性忽略（读时过滤，服务端实现）**：`ignore_fields=aspath,communities` 作用于 findings 读取与 html/csv/xlsx 导出（bundle.json 永远全量——AI 必须看到全部事实）。语义：只作用于 change=='changed' 的事实；`有效变化字段 = fields_changed − ignore 集`；为空 → 整条事实隐藏（计入 suppressed_by_ignore）；非空 → fields_changed/before/after 裁剪到有效字段后返回。added/removed 不受影响（它们表达对象存亡，不是属性变化）。这是纯读时投影：同一 compare 缓存服务任意忽略组合，零重算。

**7.8 enriched 与未 enriched 同族对比**：完全合法——两侧就是同族记录，一侧多些属性值。为消除"填充字段全行报 changed"的噪音：compare 服务检测任一侧为派生快照时，① 对比范围收窄到 derived_meta.family（其余族不产生 missing_command 噪音）；② 响应携带 `suggested_ignore_fields`（= 单侧 enriched 时该侧的 fields_filled；双侧都 enriched 时为两侧 fields_filled 的对称差）。前端把这些字段**预选**进忽略芯片（工程师可取消预选看全量）。引擎与 keyed_diff 对此零感知——这是服务层的元数据提示，不是比较语义。典型主用法 pre_enriched vs post_enriched：suggested 为空，全字段对比。

## 8. detail 前缀清单生成器

```python
Policy = Union[AllPolicy, MaskPolicy, RandomPolicy]
@dataclass(frozen=True) class AllPolicy:    kind: Literal["all"]
@dataclass(frozen=True) class MaskPolicy:   kind: Literal["mask"]; op: Literal["eq","ge","le"]; length: int
@dataclass(frozen=True) class RandomPolicy: kind: Literal["random"]; n: int; seed: int   # seed 必填

def select_prefixes(rows: list[dict], policy: Policy) -> list[dict]
# rows 来自 bgp_paths 或某 neighbor 的 received/advertised(service 层 SELECT 后传入)
# 输出去重键 (device,afi_safi,vrf,rd,prefix);random 用 random.Random(seed) 对排序后列表采样
def render_commands(items: list[dict], platform: str) -> str    # 每行一条命令,复用 §5.2.1 语法
```
落库覆盖式写 detail_plan；`GET /projects/{id}/detail-plan.txt?platform=` 下载。自洽性硬要求：render 出的每条命令必须能被 route_command 识别回 `bgp_prefix_detail` 族（test_detailplan 断言）。

## 9. REST API 契约（/api/v1；响应示例即 schema）

```
POST /projects {name} → {id,...}          GET /projects → [...]
DELETE /projects/{id} → 204(时序 D)
POST /projects/{id}/devices {device,platform} · DELETE 同路径
POST /projects/{id}/snapshots {label,kind} → {id,...}
POST /snapshots/{sid}/captures (multipart) → IngestSummary
GET  /snapshots/{sid}/coverage → [{device,command,family,params,record_count,parse_status}]
POST /projects/{id}/detail-plan {source_sid, source:{family,neighbor?,direction?,afi_safi?,vrf?}, policy}
     → {count, sample:[...前 10 条]}
GET  /projects/{id}/detail-plan.txt?platform=arista_eos|cisco_xr → text/plain
POST /projects/{id}/compares {before_sid,after_sid}
     → 202 {compare_id:"MToyOjMuMA", status:"running"}(同参数已 done → 200 直接返回旧 run)
GET  /compares/{cid}(轮询)
     → {status:"done", rules_version:"3.3", suggested_ignore_fields:[],
        finding_count:1284, artifact_path:"…",
        summary:{total:1284, by_change:{added:312,removed:296,changed:648,missing_command:2,...},
                 by_family:{bgp_paths:512,...}, by_device:{router1:...}}}
GET  /projects/{id}/compares → 运行记录列表(compare_run 登记行,含 running/failed)
POST /snapshots/{sid}/derive/enrich {family:"bgp_paths"|"bgp_neighbor_received"}
     → {snapshot_id:5, rows_total:8412, rows_matched:8210, ambiguous:3,
        fields_filled:["communities","localpref","med"]}
GET  /projects/{id}/snapshots → [{id,label,kind,taken_at,source_snapshot_id?,derived_meta?}]
     (派生快照与普通快照同列;快照选择器/对比选择器共用此接口)
POST /projects/{id}/compares/adhoc
     {a:{snapshot_id:1,device:"router1",family:"bgp_neighbor_received",
         params:{afi_safi:"ipv4_unicast",vrf:"default",neighbor:"10.1.1.1"}},
      b:{snapshot_id:1,device:"router1",family:"bgp_neighbor_received",
         params:{afi_safi:"ipv4_unicast",vrf:"default",neighbor:"10.1.1.2"}}}
     → {compare_id, rules_version, align_dropped:["neighbor"], summary:{…}}
GET  /snapshots/{sid}/instances?device=&family= → fetch_instances 结果(前端实例选择器数据源)
GET  /compares/{cid}/findings?device=&family=&afi_safi=&vrf=&change=&instance=
       &ignore_fields=aspath,communities&q=&cursor=0&limit=200
     → {items:[{device,family,instance,change,identity:{...},fields_changed:[...],
                before:{...}|null,after:{...}|null}],
        next_cursor, total_filtered, suppressed_by_ignore}
GET  /compares/{cid}/export.html|.csv|.xlsx?ignore_fields= → 文件流(缺省全量;传参则与前端所见一致)
GET  /compares/{cid}/bundle.json → §10.1
```

## 10. AI 分析接入点（接口现在定死，实现属 V2）

**10.1 bundle.json——AI 的唯一输入契约**（export/bundle.py；test_bundle_schema.py 用 JSON Schema 锁定）：
```jsonc
{ "bundle_schema_version": 1,
  "meta": { "project": "CHG0012345 …", "before": {"id":1,"label":"pre","taken_at":"…"},
            "after": {…}, "rules_version": "3.0", "generated_at": "…" },
  "summary": { /* 与 compare 响应的 summary 同构 */ },
  "coverage_facts": [ /* missing_command / unparsed 事实 */ ],
  "findings": [ { "device":"router1","family":"bgp_paths","change":"removed",
                  "identity":{"afi_safi":"vpnv4_unicast","vrf":"","rd":"65000:100",
                              "prefix":"10.50.1.0/24","peer":"10.1.1.2"},
                  "fields_changed":[], "before":{…}, "after":null } ] }
```
稳定性承诺：findings 字段名与 identity 键名随 RULES_VERSION 演进，bundle_schema_version 只在外层结构变化时递增；AI 消费方以这两个版本号做兼容判断。
**10.2 V2 analysis 模块边界**：新建 `app/analysis/`（router: `POST /compares/{cid}/analysis {focus?} → text/event-stream`）；只许 import export.bundle 与 httpx，禁止 import compare 内部；不写库；分析文本不进任何导出物（分析是易逝的观点，事实才留档）。
**10.3 前端入口**：ComparePage 右上 "AI 分析" 按钮开抽屉面板（示范见 frontend-demo.jsx），V1 即渲染入口与说明文案，按钮触达 501 占位接口。

## 11. 前端（以 prototype/frontend-demo.jsx 为视觉与交互基准）

信息架构 = 变更窗口的真实时序，用左侧**阶段轨道**表达（这是唯一允许的"编号列表"装饰，因为它就是时序）：`① 设备与命令 → ② PRE 快照 → ③ POST 快照 → ④ DETAIL（清单 + 导入）→ ⑤ 对比 → ⑥ 导出与分析`。每阶段一个主工作区。实现纪律：服务器数据全走 TanStack Query；FindingsTable 用 TanStack Virtual + 服务端分页（过滤变更即重置游标）；过滤器与 URL query 同步（刷新不丢）；删除项目需输入项目名确认。组件命名、配色语义（removed=玫红、added=祖母绿、changed=琥珀，仅此三处用色）照 demo。

**DETAIL 页（④）两个职责**：上半是清单生成向导（源快照 + 来源族 + 策略，同前）；下半是**detail 导入区**——一个"很多条命令一个文件"的采集文件上传框 + 目标快照选择（导入到 PRE 或 POST），走同一个 captures 接口（`POST /snapshots/{目标sid}/captures`），导入后即时显示"已入库 N 条 detail 记录 → PRE"。**快照页（②/③）三个 v3.3 要素**：① coverage 表中可见已导入的 detail 命令行；② "派生快照"卡片区——列出由本快照派生的 enriched 快照（含 fields_filled 与命中率）；③ "Enrich" 动作按钮：选目标族（bgp_paths / bgp_neighbor_received）→ 调 derive/enrich → 新派生快照出现在卡片区。

对比页要素（demo 已示范）：① 模式切换"自动配对 / 自定义配对"——自定义模式下两个实例选择器（数据源 `GET /snapshots/{sid}/instances`），运行后必须明示对齐说明（"neighbor 值不同 → 已从对齐键剔除，按 prefix 对齐"），前后两列表头改为"实例 A / 实例 B"；② 快照选择器包含派生快照（标注 enriched 徽记与源快照）；选中含 enriched 的组合时，`suggested_ignore_fields` 自动**预选**忽略芯片并提示原因（可取消）；③ 事实表的族列下方以浅色小字显示 instance，instance 亦为过滤器之一；④ "忽略属性"芯片行——切换即改 `ignore_fields` 参数重新拉取，表头旁显示"已因忽略隐藏 N 条 changed"。

## 12. 施工顺序与验收（顺序不可调换；验收命令原样执行）

| 步 | 内容 | 验收（全部满足才算过） |
|---|---|---|
| S1 骨架 | Makefile/config/db/空 API/空前端/CI | `make dev` 起两端；`curl :8000/api/v1/health` 200 |
| S2 数据层+分层守卫 | 全 ORM+迁移；project CRUD;时序 D;test_layering(AST 扫描 compare/spec/policy 的 import) | `pytest tests/test_project_lifecycle.py tests/test_layering.py -q` 绿；建→删项目后 `SELECT count(*)` 全表=0 |
| S3 spec+normalize | families/commands/normalize 全量 | `pytest tests/test_normalize.py tests/test_routing.py -q` 绿（含 §5.2.1 每格 ≥1 用例、归一化边角 6 例） |
| S4 ingest(EOS ipv4) | segment/parsers/arista_eos/ 逐族文件/writer/coverage/contract | `python -m app.cli ingest --dir tests/fixtures/eos/pre --label pre` 输出与 baselines/eos_ingest.json 一致；`pytest tests/test_parsers_eos.py tests/test_record_contract.py tests/test_registry_completeness.py -q` 绿（占位族在 ALLOWED_UNPARSED 中对账通过） |
| S5 compare 纯函数 | engine.keyed_diff + families/ 逐族文件 + coverage/enrich + 基准重放 | `pytest tests/test_compare_engine.py tests/test_enrich.py tests/test_coverage.py tests/test_seed_replay.py -q` 绿，须含用例：两邻居实例各自成组、其一 post 零记录时 removed 全挂对应 instance；identity 参数剔键后对齐正确；test_layering 追加断言：families/*.py 只 import engine/enrich/spec（键对齐算法不得重写）；**此步 diff 不得触碰 store/**（git diff 检查） |
| S6 compare_svc+export | 工件(原子写/流读/LRU)/异步 submit/分页/四渲染器/adhoc/ignore/derive | test_api_flows 走通时序 B/B'/C/E：POST 返回 202 running → 轮询 done → findings 可取；同参数二次 POST 直接命中旧 run 不重算；`--verify` 重算与工件逐字节一致；**重启进程后同 cid 取 findings 零重算**(工件直读)；后台异常 → status=failed 且无半成品工件；adhoc 比 nei x vs nei y 返回 align_dropped=["neighbor"] 且事实按 prefix 对齐；`ignore_fields=med` 时全 med 变化的 changed 消失、suppressed_by_ignore 计数正确、bundle.json 仍全量；derive/enrich 同源两次派生逐字节一致、prefix 三 nexthop 样例三行各自命中、多候选走 peer 优先且 ambiguous 计数正确；plain vs enriched 返回 suggested_ignore_fields=fields_filled 且范围收窄到该族；detail 聚合单元:pre 128 条/post 127 条 → 并集对比 + 1 条 missing_command；项目删除后 compare_run 行与工件目录同灭 |
| S7 XR+vpnv4+FIB | parsers/cisco_xr/ 逐族文件(route/cef 正则、bgp textfsm)、rd 归一化、add-path 样例 | `pytest tests/test_parsers_xr.py tests/test_cross_platform.py -q` 绿：同族 EOS/XR 记录字段集一致、跨平台 adhoc 冒烟(EOS route_table 实例 vs XR route_table 实例可对齐运行)；vpnv4 样例重放含 rd 的事实与基准一致；add-path 样例产出 duplicate_path_key |
| S8 detailplan | policy/render/落库/下载 | 同 seed 两次生成逐字节一致；render 输出全部可被 route_command 反向识别 |
| S9 前端 | 六阶段全流程 | 人工验收脚本：不看文档完成"建项目→传 pre→生成清单→传 post→对比→vrf 过滤→导出 xlsx→AI 面板可见→删项目"；FindingsTable 灌 10 万行 mock 滚动不卡 |

## 13. 禁止事项自查清单

不给 Finding 加 severity/分析字段；不让 compare 接受 DB 会话或文件路径；不落库 findings；不建外键；不用 SQLite 不支持的列类型；不在 router 写业务；不静默吞解析异常；不绕过配方改动注册表之外的核心文件；不引入清单外依赖；EOS FIB/vpnv4 命令定稿前保持"占位注册→unparsed"而不是猜测实现；不在 compare/families/*.py 内重写键对齐（只许前/后处理并委托 engine.keyed_diff）；不手工维护 PARSERS/COMPARATORS 映射（目录即注册）；平台目录之间不互相 import；解析器输出不引入 record_contract 之外的字段；不在对比过程中做任何数据加工（富化只能是 derive 的显式派生）；不覆盖派生快照（重派生=新快照）；派生快照不允许再被 derive（不做派生链）；不 UPDATE/追加已写成的运行工件（重跑=新 compare_id 新工件）；findings 不进关系宽表（工件文件是唯一形态）；不为异步对比引入消息队列（进程内线程池，单 worker）。

---
附：与 v2 差异——原则 1 升格明示"对比=快照库运算"；§5 全签名化；§6 四配方（低成本 AI 的唯一扩展路径）；§10 AI 接入契约（bundle.json + analysis 模块边界）；§12 每步验收给出可执行命令；前端以 frontend-demo.jsx 为基准。v3.1 增量——对比单元=命令实例（§7.5）、自由配对（§7.6）、读时属性忽略（§7.7）及配套的签名/API/前端/验收修订。v3.2 增量——目录即结构：`parsers/<平台>/<族>.py` 与 `compare/families/<族>.py`、约定式发现注册、record_contract 归一化契约与跨平台一致性测试、配方 A/B 与 S4/S5/S7 验收同步修订。v3.3 增量——富化物化为派生快照（derive 模块、snapshot 加列、匹配键 prefix+nexthop、suggested_ignore_fields）、bgp_prefix_detail 族级聚合单元、前端阶段调序与 DETAIL 导入/快照页 Enrich 动作、S6 验收扩充。v3.4 增量——对比结果物化为不可变运行工件（compare_run 登记表 + findings JSONL.gz，原则 2 重写）、对比异步化（进程内线程池 + 轮询）、四种导出与 findings 接口统一以工件为数据源、--verify 逐字节校验、删除级联工件目录。
