# netval 开发计划（原型 → 可上线产品）

> 结论先行：这个产品**只需要 1 个 Python 服务（FastAPI 模块化单体）+ 1 个数据库（验证期 SQLite，生产 PostgreSQL）+ 1 个 React 前端**，外加一个复用同一套包的 CLI。不需要微服务，不需要消息队列，不需要缓存服务——对比是毫秒到秒级的纯函数计算，结果放进程内存缓存即可；数据库因为"项目导出即删"的生命周期长期保持小体积。下面是依据和完整执行方案。配套施工图见 ENGINEERING_SPEC_v2.md（本文不重复其细节，只给决策依据、工期与风险）。

---

## 1. 总体架构与"为什么只要一个服务一个库"

整个系统的本质是：一条**入库流水线**（采集文本 → 切分 → 命令路由 → 解析 → 六张宽表），加一组**对宽表的纯函数**（覆盖率对齐、属性富化、键对齐对比），再加一组**渲染器**（HTML / CSV / XLSX / 前端事实表）。数据规模上，一个项目（100 台设备、全路径 BGP、双 AFI、前后两快照）约一两千万行、2–4 GB——这是单库毫无压力的量级，且项目结束即整体删除，数据库常态只装着进行中的少数项目。计算上，一次全量对比是"按索引取两批行 + 内存哈希对齐"，逐实例取数逐实例释放（峰值内存 = 最大单实例，不是整快照）；百设备规模整体是分钟级计算，因此对比**异步执行**——进程内线程池（单 worker）+ compare_run 状态轮询，依然不需要消息队列。对比结果物化为**不可变运行工件**（compare_run 登记行 + findings JSONL.gz 文件）：它是纯函数的 memoization 而非可变状态——findings 接口、HTML/CSV/XLSX 导出、AI 用的 bundle.json 全部以这一个工件为唯一数据源，进程重启零重算，同参数重跑直接命中旧工件，项目删除时随项目级联清理。因此后端是一个 FastAPI 单体，内部按模块分包（spec / ingest / store / compare / derive / detailplan / export），模块边界即未来的拆分边界，但现在不拆。

```
netval/
├── frontend/                # React + TS(1 个 SPA):项目工作台、上传、对比事实表、导出
├── backend/app/
│   ├── spec/                # 声明层:族规范、命令路由、归一化 —— 一切扩展点
│   ├── ingest/              # 切分 + 解析插件(EOS json / XR 文本)+ 入库
│   ├── store/               # 六张宽表的批量写与读
│   ├── compare/             # 对比引擎(纯函数,零 IO)—— 产品的灵魂
│   ├── compare_svc/         # 编排 + 进程内结果缓存 + 分页过滤 API
│   ├── detailplan/          # detail 前缀清单生成器(all/mask/random+seed)
│   ├── export/              # html / csv / xlsx
│   └── project/             # 项目/快照生命周期,删除级联
└── data/netval.db           # SQLite(生产换 PostgreSQL,零代码修改)
```

部署形态：`docker compose up` 两个容器（frontend nginx、backend uvicorn），SQLite 阶段没有 db 容器。技术选型固定：后端 FastAPI + SQLAlchemy 2 + Pydantic v2 + Alembic + openpyxl，XR 文本解析接 ntc-templates/TextFSM；前端 React 18 + TypeScript + TanStack Query/Table/Virtual + Zustand；测试 pytest + httpx，对比引擎以原型样例重放为行为基准。

## 2. 数据库设计决策摘要（细节见施工图 §4）

六条已定案原则：**每族一张类型化宽表**（按 snapshot_id + device 筛选）；**BGP 存全路径**而非仅最优（路径冗余丢失必须可见，"路径缺失"自然表现为 removed 行）；**afi_safi + rd 两列**承载 ipv4 unicast / vpnv4 双地址族，pre/post 必须同视角采集；**findings 不落库**（对比是纯函数，留档靠导出文件，引擎语义以 ENGINE_RULES_VERSION 版本化写入导出物）；**原始 CLI 文本不进库**（可选 gzip 归档文件系统，供解析器修复后重算）；**无外键、宽表无主键、多值字段标量化**（批量写 + 整值比 + 整快照删的负载不需要它们）。表清单：project / project_device / snapshot / detail_plan / command_coverage + 五张数据宽表（route_table、forwarding_table、bgp_paths、bgp_neighbor_routes、bgp_prefix_detail）。command_coverage 是"不存原文"的必要补偿——没有它，"邻居挂了收到 0 条"与"命令没采集"无法区分。

## 3. 对比引擎（backend/app/compare，产品的灵魂）

必须是**纯函数、零数据库依赖**：输入前后两批记录字典与族规范，输出 Finding 列表。这样单元测试极其好写，CLI 与 API 复用同一引擎，缓存失效后确定性重算。流程：覆盖率对齐（missing_command / unparsed 作为事实产出，不阻断）→ 按命令实例键对齐（added / removed / changed 三类事实，逐字段前后值；detail 族按设备级聚合为单一对比单元）。**富化不在对比过程中发生**——它是快照页上的显式派生动作（derive/enrich）：以 prefix+nexthop 匹配 detail 路径属性，产出 kind='enriched' 的派生快照（记录填充字段与命中率），派生快照与普通快照在对比中完全同权；enriched 与未 enriched 同族对比时服务端预选忽略被填充字段以消噪。**引擎不做重要性判断**：没有 severity，没有聚合，没有"疑似会话中断"这类推断——报告陈述事实，分析留给工程师，V2 留给 AI。这条边界是本产品与"智能分析工具"的刻意区隔，也让引擎的正确性可以用"事实集深度相等"来验收。

## 4. API 设计（REST，OpenAPI 自动生成前端客户端）

```
GET/POST /projects · GET/DELETE /projects/{id}            -- DELETE 级联清空全部数据
POST/DELETE /projects/{id}/devices                        -- 设备清单(覆盖率期望集)
POST /projects/{id}/snapshots {label, kind:pre|post|adhoc}
POST /snapshots/{sid}/captures (multipart)                -- 返回 ingest 摘要含 unparsed 清单
GET  /snapshots/{sid}/coverage
POST /projects/{id}/detail-plan {source_sid, policy}      -- all | mask(eq/ge/le,L) | random(N,seed)
GET  /projects/{id}/detail-plan.txt?platform=eos|xr       -- 渲染命令清单下载
POST /projects/{id}/compares {before_sid, after_sid}      -- 返回 compare_id + 分维度计数
GET  /compares/{cid}/findings?device=&family=&afi_safi=&vrf=&change=&q=&cursor=
GET  /compares/{cid}/export.html|.csv|.xlsx
```

体验关键在两处：captures 的即时摘要（哪台设备哪条命令没解析，当场可见，采集纪律靠反馈而不是靠文档）；findings 的服务端过滤分页（事实集可到十万行，前端只做虚拟窗口渲染）。

## 5. 前端模块

四页：**项目列表**（新建/打开/删除，删除要求输入项目名确认）；**项目工作台**（设备清单、快照卡片、拖拽上传与 ingest 反馈、detail 清单三步向导：源快照→来源族→策略）；**快照覆盖页**（设备×命令矩阵，record_count 与 parse_status）；**对比页**（选两快照→按设备/族/变化类型的计数摘要→事实表：TanStack Table + Virtual 虚拟滚动，六个过滤器 device/family/afi_safi/vrf/change/全文，前后值双列红绿底色→三格式导出按钮）。状态纪律：服务器数据全走 TanStack Query，Zustand 只放 UI 态。

## 6. 里程碑计划（1 名全栈 + 领域评审即你本人；人日为开发净工时）

| 阶段 | 内容 | 工期 | 退出标准 |
|---|---|---|---|
| M0 脚手架 | compose、FastAPI+Alembic、Vite 空页、CI、OpenAPI 客户端生成 | 4 人日 | 一条命令起全栈 |
| M1 数据底座 | 全部表迁移、project/snapshot CRUD、删除级联 | 5 人日 | 建→删项目后全表 count=0 |
| M2 ingest(EOS ipv4) | 切分、命令路由、eos_json 四族解析、coverage、批量写 | 7 人日 | 原型样例上传后各表行数与基准一致 |
| M3 对比引擎+派生+工件+导出 | compare 纯函数包、derive/enrich 派生快照、运行工件(JSONL.gz+登记表+异步 submit)、分页过滤 API、三格式导出 | 9 人日 | 样例重放事实集与基准深度相等；--verify 重算与工件逐字节一致；重启零重算 |
| M4 vpnv4+FIB+XR | afi_safi/rd 归一化、cef/route 正则、bgp 接 ntc-templates、EOS FIB 命令定稿 | 10 人日 | vpnv4(含 RD)与 FIB 样例全链路通过 |
| M5 detail 生成器 | policy/render/落库、与命令路由的反向识别自洽 | 3 人日 | 同 seed 两次生成逐字节一致 |
| M6 前端 | 阶段轨道(设备→PRE→POST→DETAIL 清单+导入→对比→导出)、上传反馈、快照页 Enrich 动作、虚拟滚动事实表、忽略芯片、导出、删除 | 13 人日 | 工程师不看文档走完全流程(含派生与 enriched 对比) |
| —— V1 上线 —— | 累计约 **51 人日 ≈ 10 周**（单人） | | 真实变更窗口试用一次 |
| M7 AI 分析(V2) | findings 喂 LLM:摘要、异常提示、重要性标注(引擎外挂,不进 compare 包) | 5 人日 | 对比页出"AI 分析"面板 |
| M8 采集器(V2) | Collector 抽象落地:SSH(Scrapli)采集器或整链路封装 MCP 工具供 agent 调用 | 8 人日 | agent 可自主完成采集→对比→读事实 |

## 7. 关键决策点与风险

第一，**XR 文本解析是全项目最大风险**（M4 独占 10 人日的原因）：vpnv4 输出的 RD 分段、cef 的递归下一跳与标签栈、ntc-templates 对 XR BGP 命令的覆盖缺口都可能要自写模板；缓冲 2 人日，且靠"原文 gzip 归档 + 重算"机制兜底——解析错了修模板重放，不丢数据。第二，**EOS FIB 命令待实测定稿**（候选 `show fib route`，以你环境的 EOS 版本确认，这是目前唯一需要你拍板的技术确认项）。第三，**采集视角纪律**：vpnv4 全局视图与 per-vrf 视图混用会导致键对不齐，产品层面靠"项目命令计划固化 + coverage 即时反馈"约束，不在引擎里做兼容。第四，**add-path 同键路径**：引擎并入 nexthop 做第六键成分并产出 duplicate_path_key 事实，不静默处理。第五，**前端大表渲染**：十万行级事实集必须虚拟滚动 + 服务端过滤，M6 已按此估工。

## 8. 从原型到 V1 的直接复用清单

原型（netval-proto，已端到端验证）可直接翻译或移植的部分：`segment.py` 的 marker 切分原样用；`spec.py` 的命令路由正则表扩展 afi_safi 后沿用；`arista_json.py` 的访问器结构扩全路径与 vpnv4 字段；`diff.py` 的键对齐算法去掉 severity 即为 compare/engine；`report_html.py` / `report_tabular.py` 去 severity 列后即为 export 包；`iosxr_text.py` 的 route 正则进 xr_text。样例数据升级为 M2/M3 的验收基准（补 vpnv4 与 FIB 样例）。也就是说 M2 与 M3 的核心逻辑是"翻译+加固"而非从零设计，工期按此估定；真正的新增开发集中在 M4（XR/vpnv4/FIB）与 M6（前端）。
