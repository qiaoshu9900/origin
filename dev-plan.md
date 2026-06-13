# Fabric Planner 开发计划(原型 → 可上线产品)

> 结论先行:这个产品**只需要 1 个 Python 服务(FastAPI 模块化单体)+ 1 个 PostgreSQL 数据库 + 1 个 React 前端**。不需要微服务,不需要图数据库,不需要消息队列(导出异步化可在 V2 用一个进程内任务队列解决)。下面是依据和完整执行方案。

---

## 1. 总体架构与"为什么只要一个服务一个库"

整个系统的本质是:一份结构化的设计数据(域树 / 设备 / 端口 / 连线),加一组对它的纯函数(连线生成、端口分配、校验),再加一组派生视图(图、BOM、Patching 表、IP 表)。数据规模上,一个大型数据中心设计通常是几百台设备、几千个端口占用、几千根线 —— 这是 PostgreSQL 单库毫无压力的量级,关系查询(JOIN + 递归 CTE 查域树)完全够用,图数据库属于过度设计。计算上,连线生成和端口分配是毫秒级的内存运算,不需要独立计算服务。因此后端是一个 FastAPI 单体,内部按模块分包,模块边界清晰,未来真有需要时任何一个模块都能拆出去。

```
fabric-planner/
├── frontend/                 # React + TypeScript(1 个 SPA)
│   ├── canvas/               #   HLD 画布(React Flow)
│   ├── lld/                  #   域 LLD 视图、设备详情、规则表单
│   ├── views/                #   组合图、BOM、Patching、IPAM 页面
│   └── api/                  #   OpenAPI 自动生成的客户端
├── backend/                  # FastAPI 单体(1 个 Python 服务)
│   └── app/
│       ├── catalog/          #   设备型号库(导入 NetBox devicetype-library)
│       ├── design/           #   设计/域树/设备 CRUD
│       ├── rules/            #   规则引擎:pattern 生成器 + 端口分配器 + 校验器(纯函数,零 IO)
│       ├── derive/           #   派生:BOM、Patching、布局、diff
│       ├── export/           #   xlsx / SVG / JSON 导出
│       ├── ipam/             #   V2:IP 池与分配(或代理 NetBox)
│       └── snapshot/         #   版本快照与对比
└── postgres/                 # 1 个 PostgreSQL 16(含 Alembic 迁移)
```

部署形态:`docker compose up` 三个容器(frontend nginx、backend uvicorn、postgres)。内部工具不需要更多。

技术选型固定如下:前端 React 18 + TypeScript + **React Flow(@xyflow/react)** 做画布、**elkjs** 做 LLD 自动布局、Zustand 管状态、TanStack Query 对接 API;后端 **FastAPI + SQLAlchemy 2 + Pydantic v2 + Alembic**,导出用 **openpyxl**(xlsx)和 **svgwrite/前端导出**(图);测试 pytest + Hypothesis(对分配器做属性测试)。

## 2. 数据库设计(单库,核心 11 张表)

最重要的设计决策:**端口要不要物化成表行?** 原型里端口是"型号模板按需展开"的虚拟概念,省事但有两个问题 —— IPAM 阶段 IP 要落在接口上,以及 breakout/预留/手工锁定都需要给端口挂状态。所以正式版采用 NetBox 同款做法:**创建设备时按型号模板批量生成 interface 行**。一台 48 口交换机生成 ~54 行,一千台设备也才 5 万行,完全没有性能问题,换来的是干净的外键关系(link 端点、IP 分配都指向 interface.id)。

```sql
-- 设计与域树 ----------------------------------------------------
design          (id, name, status, created_at, ...)        -- 一个 DC 项目;双活就是两个 design 或同 design 两棵树
block_template  (id, key, label, allowed_children jsonb)   -- DC Core / External / ... 模板目录
block           (id, design_id, template_key, name,
                 parent_id REFERENCES block(id),            -- 任意深度域树,递归 CTE 查询
                 pos_x, pos_y, sort_order)
block_relation  (id, design_id, a_block, b_block, kind)    -- HLD 层面的"块间规划关系"

-- 设备与端口 ----------------------------------------------------
device_model    (id, vendor, model, meta jsonb)             -- 从 devicetype-library YAML 导入
port_template   (id, model_id, name_pattern, idx_from, idx_to,
                 speed_g, media, breakout_speeds int[])     -- breakout 能力在这里声明
device          (id, block_id, model_id, name, role, seq)
interface       (id, device_id, name, speed_g, media,
                 parent_if REFERENCES interface(id),        -- breakout 子口指向父口
                 state)                                     -- free / used / broken_out / reserved

-- 连线(规则生成,禁止手工插行)---------------------------------
link_group      (id, design_id, owner_block, kind,          -- internal / cross
                 params jsonb,                              -- {pattern, per, speed, target_block, allow_breakout}
                 label)
link            (id, group_id, a_if REFERENCES interface(id),
                 b_if REFERENCES interface(id),
                 speed_g, media, tag,
                 UNIQUE(a_if), UNIQUE(b_if) DEFERRABLE)     -- 一个接口只能接一根线,数据库层兜底

-- 版本与 IPAM(V2)----------------------------------------------
snapshot        (id, design_id, label, payload jsonb, created_at)  -- 整体设计 JSON 快照,用于 diff/回滚
ip_pool         (id, design_id, prefix cidr, purpose)              -- p2p / loopback / mgmt
ip_assignment   (id, pool_id, interface_id, address inet)          -- 点对点 /31 成对分配
```

几条配套规则写进应用层事务:删 link_group 必须级联删 link 并把 interface.state 复位;breakout 创建是"父口置 broken_out + 生成 4 个子口行"一个事务;所有写操作带 design 级乐观锁(version 字段),防止两人同时改一个设计。

## 3. 规则引擎(backend/app/rules,产品的灵魂)

这一包必须是**纯函数、零数据库依赖**:输入设备+端口快照和参数,输出"将要创建的 link 列表 + 将要发生的 breakout 列表 + 校验警告",由外层 service 负责落库。这样单元测试极其好写,前端"预览将生成的连线"也直接复用同一接口(dry-run 模式)。

内部三个组件。第一,**Pattern Registry**:full_mesh、ring(手拖手)、cross_full_mesh(上联),以及预留的 spine_leaf、dual_homed(成对接入)、mlag_pair;每个 pattern 是一个 `(devices, params) -> [(devA, devB)]` 的配对函数,新拓扑模式只需注册新函数。第二,**端口分配器**:策略可配置 —— peer/uplink 从高位口降序、downlink 从低位口升序(沿用原型已验证的规则),速率必须匹配,原生口用尽且允许 breakout 时自动拆分(可配置拆分速率),同一对设备的多根线尽量分配在连续端口,未来可加"奇偶分槽位防单板故障"策略。第三,**校验器**:速率是否被型号支持(报错时给出该型号支持的速率清单)、端口余量预检(生成前先算总需求,不够直接拒绝而不是生成一半)、双上联对称性警告、跨域连线是否违反 HLD 规划关系(警告而非阻断)。

## 4. API 设计(REST,OpenAPI 自动生成前端客户端)

```
GET/POST/PATCH/DELETE  /designs, /designs/{id}/blocks, /blocks/{id}
POST  /blocks/{id}/devices              {model_id, count}        -- 批量建设备并展开 interface
GET   /devices/{id}/interfaces          ?state=free&speed=100    -- 设备端口明细(详情抽屉的数据源)
POST  /interfaces/{id}/breakout         {child_speed} | DELETE 恢复
POST  /link-groups/preview              规则 dry-run:返回将生成的线、将拆分的口、警告
POST  /link-groups                      正式生成(同一引擎,落库)
DELETE /link-groups/{id}                级联删线、复位端口
GET   /designs/{id}/topology            ?blocks=a,b,c            -- 框选组合图数据(节点+边)
GET   /designs/{id}/bom                 ?block=x&include_children=true
GET   /designs/{id}/patching.xlsx       ?block=x                 -- openpyxl 流式导出
POST  /designs/{id}/snapshots, GET /snapshots/{a}/diff/{b}       -- 增量 patching 的基础
POST  /catalog/import-devicetype        上传/同步 devicetype-library YAML
```

`preview` 接口是体验关键:前端表单一变就调它,用户在点"生成"之前就能看到"将新增 16 根线、INET-DIST-01 的 Eth1/1 将拆分为 4×25G、警告:Eth 余量仅剩 2 口"。

## 5. 前端模块

页面与原型一一对应,五个:HLD 画布(React Flow 自定义节点 + 分组节点表达域嵌套,拖拽坐标只是视图属性回存 block.pos)、域 LLD(elkjs 分层布局,规则表单接 preview,设备详情抽屉)、组合视图(框选 = 传 block id 集合给 /topology)、BOM(域树选择器 + 含子域开关)、Patching(过滤 + 导出)。两个全局件:设计选择器/快照对比页,以及型号库管理页(浏览导入的 devicetype,标注端口角色)。图导出在前端做(React Flow → SVG/PNG),表格导出走后端 xlsx。

## 6. 里程碑计划(1 名全栈 + 1 名网络工程师做领域评审;人日为开发净工时)

| 阶段 | 内容 | 工期 | 退出标准 |
|---|---|---|---|
| M0 脚手架 | docker compose、FastAPI+Alembic、React+RF 空画布、CI、OpenAPI 客户端生成 | 5 人日 | 一条命令起全栈,建一个空 design |
| M1 数据底座 | 11 张表迁移、devicetype-library 导入器(先支持 Cisco/Arista 两目录)、设备创建展开 interface | 8 人日 | 导入 ≥50 个真实型号;建 4 台设备生成正确端口行 |
| M2 规则引擎 | pattern registry + 分配器 + breakout + 校验器 + preview API;Hypothesis 属性测试(不重复分配、删组后端口全复位) | 10 人日 | 原型里的 5 个种子场景在真库上重放结果一致 |
| M3 HLD/LLD UI | 画布、域树、规则表单+预览、设备详情抽屉、elkjs 布局 | 12 人日 | 网络工程师不看文档能完成一个三层 External 设计 |
| M4 派生输出 | 组合图、按域 BOM、patching xlsx、SVG 导出 | 6 人日 | 导出文件可直接发下游 patching 团队使用 |
| M5 快照与 diff | snapshot、两版本连线 diff(新增/删除线清单 → 增量 patching 表) | 5 人日 | 修改设计后能导出"只做这些跳线"的工单 |
| —— V1 上线 —— | 累计约 **46 人日 ≈ 9–10 周**(单人) | | 团队内部试用 |
| M6 IPAM(V2) | ip_pool、p2p /31 成对分配、loopback/mgmt 顺序分配、IP 表导出;或:对接 NetBox IPAM API 二选一 | 8 人日 | 每根三层链路有 /31,导出 IP 规划表 |
| M7 协同与集成(V2) | 多用户乐观锁提示、设计推送 NetBox(竣工态)、DAC/AOC 介质与光模块选型(SR/LR 按距离) | 10 人日 | 设计定稿一键进 NetBox |

## 7. 关键决策点与风险

第一,**NetBox 的角色**:不要拿 NetBox 当设计工具(它是登记竣工态的 DCIM,没有"按规则批量生成连线"的概念),但要最大化复用它 —— devicetype-library 当型号库种子、IPAM 可直接代理、设计定稿后推送过去作为运维真相源。第二,**坚持"连线只能由规则生成"**:这是数据一致性的生命线,UI 上永远不提供手画线;特殊场景用"单对设备的 cross 规则"覆盖。第三,**端口角色标注**是导入型号后唯一需要人工补充的元数据(哪些口习惯做 uplink),给型号库页面留好编辑入口,有默认推断(高速口=fabric)。第四,风险主要在 M3 的画布交互打磨(嵌套分组节点的拖拽体验)和 elkjs 布局调参,各预留 2 人日缓冲;M2 的分配器逻辑已被本原型验证过,风险低。

## 8. 从原型到 V1 的直接复用清单

原型中可原样翻译成 Python 的部分:`buildGroupLinks`(配对 + 逐对分配)、`allocPort`(降序/升序 + breakout 触发)、`effectivePorts`(breakout 展开)、`countOptics`(分支线归并统计)、`supportsSpeed` 与错误文案逻辑;前端可直接搬走的:速率配色、域树组件、设备详情抽屉、BOM/Patching 表结构。也就是说 M2 的核心算法和 M3/M4 的交互方案都已经过验证,计划里的工期是按"翻译+加固"而不是"从零设计"估的。
