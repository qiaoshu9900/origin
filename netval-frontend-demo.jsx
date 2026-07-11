import { useState, useMemo } from "react";
import {
  Server, Upload, FileDown, Sparkles, Plus, Check, Search,
  Trash2, Download, Terminal, Loader2, ChevronRight, ArrowRight, X,
} from "lucide-react";

/* ────────────────────────────────────────────────────────────────
   netval 前端示范 · 视觉与交互基准 (对应 ENGINEERING_SPEC_v3 §11)
   信息架构 = 变更窗口真实时序,由左侧阶段轨道表达。
   色彩纪律:动作色仅 teal;rose/emerald/amber 严格保留给
   removed/added/changed 语义,别处不用。数据一律等宽字体。
──────────────────────────────────────────────────────────────── */

const FONT = `@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
.f-disp{font-family:'Space Grotesk',ui-sans-serif,system-ui,sans-serif}
.f-mono{font-family:'IBM Plex Mono',ui-monospace,Consolas,monospace}`;

/* ── mock 数据 ─────────────────────────────────────────────── */
const PROJECTS = [
  { id: 1, name: "CHG0012345 骨干 MED 策略调整", status: "进行中", devices: 2, snaps: "pre ✓ · post ✓", created: "2026-07-10" },
  { id: 2, name: "CHG0011980 PE2 升级验证", status: "已导出", devices: 6, snaps: "pre ✓ · post ✓", created: "2026-07-02" },
];
const DEVICES = [
  { device: "router1", platform: "arista_eos", cmds: 9 },
  { device: "router2", platform: "cisco_xr", cmds: 11 },
];
const SNAPSHOTS = [
  { id: 1, kind: "pre", label: "pre-change", taken: "07-10 21:40", records: 48210, cov: "20/20" },
  { id: 2, kind: "post", label: "post-change", taken: "07-11 01:15", records: 47882, cov: "19/20" },
];
const COVERAGE = [
  { device: "router1", command: "show ip bgp | json", family: "bgp_paths", n: 8412, st: "ok" },
  { device: "router1", command: "show ip route | json", family: "route_table", n: 6120, st: "ok" },
  { device: "router1", command: "show ip bgp neighbors 10.1.1.1 routes | json", family: "bgp_neighbor_received", n: 4021, st: "ok" },
  { device: "router1", command: "show ip bgp neighbors 10.1.1.2 routes | json", family: "bgp_neighbor_received", n: 0, st: "ok" },
  { device: "router2", command: "show bgp vpnv4 unicast", family: "bgp_paths", n: 9330, st: "ok" },
  { device: "router2", command: "show cef vrf CUST1 ipv4", family: "forwarding_table", n: 0, st: "missing" },
  { device: "router2", command: "show route vrf CUST1", family: "route_table", n: 5233, st: "ok" },
];
const F = (device, family, change, identity, fields, before, after) =>
  ({ device, family, change, identity, fields, before, after });
const FINDINGS = [
  F("router2", "coverage", "missing_command", { command: "show cef vrf CUST1 ipv4" }, [],
    { present: "yes" }, { present: "no — 该实例未对比" }),
  F("router1", "bgp_paths", "removed",
    { afi_safi: "ipv4_unicast", vrf: "default", rd: "", prefix: "10.50.1.0/24", peer: "10.1.1.2" }, [],
    { nexthop: "10.1.1.2", aspath: "65020 65100", med: 0, localpref: 100, best: 0, valid: 1 }, null),
  F("router2", "bgp_paths", "removed",
    { afi_safi: "vpnv4_unicast", vrf: "", rd: "65000:100", prefix: "10.50.1.0/24", peer: "10.1.1.2" }, [],
    { nexthop: "10.1.1.2", aspath: "65020 65100", med: 0, localpref: 100, best: 0 }, null),
  F("router1", "bgp_paths", "changed",
    { afi_safi: "ipv4_unicast", vrf: "default", rd: "", prefix: "10.50.1.0/24", peer: "10.1.1.1" },
    ["med", "best"], { med: 0, best: 0 }, { med: 50, best: 1 }),
  F("router1", "bgp_paths", "added",
    { afi_safi: "ipv4_unicast", vrf: "default", rd: "", prefix: "10.99.0.0/16", peer: "10.1.1.1" }, [],
    null, { nexthop: "10.1.1.1", aspath: "65010 65999", med: 0, localpref: 100, best: 1, valid: 1 }),
  F("router1", "route_table", "removed", { vrf: "default", prefix: "192.168.1.0/24" }, [],
    { protocol: "eBGP", nexthops: "10.1.1.2@Et2", preference: 200 }, null),
  F("router1", "route_table", "added", { vrf: "default", prefix: "10.99.0.0/16" }, [],
    null, { protocol: "eBGP", nexthops: "10.1.1.1@Et1", preference: 200 }),
  F("router2", "route_table", "changed", { vrf: "CUST1", prefix: "10.30.0.0/24" },
    ["nexthops"], { nexthops: "10.9.9.1@" }, { nexthops: "10.9.9.2@" }),
  F("router2", "forwarding_table", "changed", { vrf: "CUST1", prefix: "10.20.0.0/24" },
    ["labels"], { labels: "24005" }, { labels: "24011" }),
  F("router1", "forwarding_table", "changed", { vrf: "default", prefix: "10.50.1.0/24" },
    ["nexthops"], { nexthops: "10.1.1.1@Et1 10.1.1.2@Et2" }, { nexthops: "10.1.1.1@Et1" }),
  ...["192.168.1.0/24", "192.168.2.0/24", "172.20.0.0/16", "10.60.0.0/24"].map((p) =>
    F("router1", "bgp_neighbor_received", "removed",
      { afi_safi: "ipv4_unicast", vrf: "default", rd: "", neighbor: "10.1.1.2", prefix: p }, [],
      { nexthop: "10.1.1.2", aspath: "65020", med: 0, localpref: 100 }, null)),
  F("router1", "bgp_neighbor_received", "changed",
    { afi_safi: "ipv4_unicast", vrf: "default", rd: "", neighbor: "10.1.1.1", prefix: "10.50.1.0/24" },
    ["med", "communities"], { med: 0, communities: "65010:100" }, { med: 50, communities: "65010:200" }),
  F("router1", "bgp_neighbor_advertised", "changed",
    { afi_safi: "ipv4_unicast", vrf: "default", rd: "", neighbor: "10.1.1.1", prefix: "172.16.0.0/24" },
    ["aspath"], { aspath: "65001" }, { aspath: "65001 65001 65001" }),
  F("router2", "bgp_paths", "added",
    { afi_safi: "vpnv4_unicast", vrf: "", rd: "65000:200", prefix: "10.40.0.0/24", peer: "192.0.2.1" }, [],
    null, { nexthop: "192.0.2.1", aspath: "65030", med: 0, localpref: 100, best: 1 }),
];
const SUMMARY = { added: 3, removed: 8, changed: 6, coverage: 1 };
const AI_TEXT = [
  "· 邻居 10.1.1.2 (router1) 的 4 条 received 路由与 2 条 bgp_paths 路径全部消失,且该邻居 post 记录数为 0——模式与会话中断一致,建议核对会话状态。",
  "· 10.50.1.0/24 冗余路径 2 → 1,最优路径切至 10.1.1.1 且 MED 0 → 50;FIB 下一跳集合同步收敛。与本次变更(MED 策略)预期一致,但冗余丢失需确认是否可接受。",
  "· router2 的 show cef vrf CUST1 ipv4 在 post 缺失,转发面变化未被验证——建议补采后重新对比。",
];

/* 忽略属性芯片:读时过滤,对应 findings 接口 ignore_fields 参数 */
const IGN_CHIPS = [
  { label: "aspath", fields: ["aspath"] },
  { label: "med", fields: ["med"] },
  { label: "localpref", fields: ["localpref"] },
  { label: "communities", fields: ["communities"] },
  { label: "nexthop", fields: ["nexthop", "nexthops"] },
  { label: "origin", fields: ["origin"] },
  { label: "best/valid", fields: ["best", "valid"] },
  { label: "labels", fields: ["labels"] },
];

/* 自由配对示例:同一 PRE 快照内,邻居 10.1.1.1 vs 10.1.1.2 的 received 视角对比 */
const ADHOC = {
  a: "#1 pre · router1 · received · nei 10.1.1.1",
  b: "#1 pre · router1 · received · nei 10.1.1.2",
  align: "实例参数中 neighbor 值不同 → 已从对齐键剔除;按 (afi_safi, vrf, prefix) 对齐,neighbor 为对比轴",
  findings: [
    F("router1", "bgp_neighbor_received", "removed",
      { afi_safi: "ipv4_unicast", vrf: "default", prefix: "10.20.0.0/16" }, [],
      { nexthop: "10.1.1.1", aspath: "65010", med: 10, localpref: 100 }, null),
    F("router1", "bgp_neighbor_received", "removed",
      { afi_safi: "ipv4_unicast", vrf: "default", prefix: "10.99.0.0/16" }, [],
      { nexthop: "10.1.1.1", aspath: "65010 65999", med: 0 }, null),
    F("router1", "bgp_neighbor_received", "added",
      { afi_safi: "ipv4_unicast", vrf: "default", prefix: "192.168.1.0/24" }, [],
      null, { nexthop: "10.1.1.2", aspath: "65020", med: 0 }),
    F("router1", "bgp_neighbor_received", "changed",
      { afi_safi: "ipv4_unicast", vrf: "default", prefix: "10.50.1.0/24" },
      ["nexthop", "aspath", "med"],
      { nexthop: "10.1.1.1", aspath: "65010 65100", med: 0 },
      { nexthop: "10.1.1.2", aspath: "65020 65100", med: 20 }),
  ],
};

/* ── 原子组件 ─────────────────────────────────────────────── */
const CHG = {
  added: { label: "added", bar: "border-l-emerald-500", chip: "bg-emerald-50 text-emerald-700" },
  removed: { label: "removed", bar: "border-l-rose-500", chip: "bg-rose-50 text-rose-700" },
  changed: { label: "changed", bar: "border-l-amber-500", chip: "bg-amber-50 text-amber-700" },
  missing_command: { label: "coverage", bar: "border-l-stone-400", chip: "bg-stone-100 text-stone-600" },
};
const Chip = ({ c, children }) => (
  <span className={`f-mono inline-block rounded px-1.5 py-0.5 text-xs font-medium ${c}`}>{children}</span>
);
const KV = ({ d, hl = [] }) =>
  d ? (
    <div className="f-mono text-xs leading-5">
      {Object.entries(d).map(([k, v]) => (
        <div key={k} className={hl.includes(k) ? "font-semibold" : "text-stone-600"}>
          <span className="text-stone-400">{k}=</span>{String(v)}
        </div>
      ))}
    </div>
  ) : <span className="text-stone-300">—</span>;

/* ── 阶段轨道(签名元素) ───────────────────────────────────── */
const STAGES = [
  { id: "devices", n: "1", t: "设备与命令", s: "2 台 · 计划 20 条" },
  { id: "pre", n: "2", t: "PRE 快照", s: "已入库 · 20/20" },
  { id: "post", n: "3", t: "POST 快照", s: "已入库 · 19/20" },
  { id: "detail", n: "4", t: "DETAIL 清单 + 导入", s: "128 条 · 可入 PRE/POST" },
  { id: "compare", n: "5", t: "对比", s: "现算 · 不落库" },
  { id: "export", n: "6", t: "导出与分析", s: "html / csv / xlsx" },
];
function StageRail({ stage, setStage, done }) {
  return (
    <nav className="w-56 shrink-0 border-r border-stone-200 bg-white py-4">
      {STAGES.map((s, i) => {
        const active = stage === s.id;
        const isDone = done.includes(s.id);
        return (
          <button key={s.id} onClick={() => setStage(s.id)}
            className={`group relative flex w-full items-start gap-3 px-5 py-3 text-left transition-colors ${active ? "bg-teal-50" : "hover:bg-stone-50"}`}>
            {i < STAGES.length - 1 && <span className="absolute left-8 top-10 h-6 w-px bg-stone-200" />}
            <span className={`f-disp z-10 flex h-6 w-6 items-center justify-center rounded-full text-xs font-semibold
              ${active ? "bg-teal-700 text-white" : isDone ? "bg-teal-100 text-teal-700" : "bg-stone-100 text-stone-400"}`}>
              {isDone && !active ? <Check size={13} /> : s.n}
            </span>
            <span>
              <span className={`block text-sm font-medium ${active ? "text-teal-900" : "text-stone-700"}`}>{s.t}</span>
              <span className="f-mono block text-xs text-stone-400">{s.s}</span>
            </span>
          </button>
        );
      })}
    </nav>
  );
}

/* ── 各阶段面板 ───────────────────────────────────────────── */
const Panel = ({ title, sub, right, children }) => (
  <section className="mx-auto max-w-5xl px-8 py-6">
    <div className="mb-4 flex items-end justify-between">
      <div>
        <h2 className="f-disp text-lg font-semibold text-stone-900">{title}</h2>
        {sub && <p className="mt-0.5 text-sm text-stone-500">{sub}</p>}
      </div>
      {right}
    </div>
    {children}
  </section>
);
const Card = ({ children, className = "" }) => (
  <div className={`rounded-lg border border-stone-200 bg-white ${className}`}>{children}</div>
);
const Th = ({ children }) => <th className="px-4 py-2 text-left text-xs font-semibold text-stone-500">{children}</th>;
const Td = ({ children, mono, className = "" }) => (
  <td className={`px-4 py-2 align-top text-sm ${mono ? "f-mono text-xs" : ""} ${className}`}>{children}</td>
);

function DevicesStage() {
  return (
    <Panel title="设备与命令计划" sub="设备清单即覆盖率期望集;命令计划固化后,pre/post 用同一份采集"
      right={<button className="flex items-center gap-1.5 rounded-md bg-teal-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-800"><Plus size={15} />添加设备</button>}>
      <Card>
        <table className="w-full">
          <thead className="border-b border-stone-100"><tr><Th>设备</Th><Th>平台</Th><Th>命令计划</Th><Th /></tr></thead>
          <tbody>
            {DEVICES.map((d) => (
              <tr key={d.device} className="border-b border-stone-50 last:border-0">
                <Td mono className="font-medium text-stone-900">{d.device}</Td>
                <Td mono><Chip c="bg-stone-100 text-stone-600">{d.platform}</Chip></Td>
                <Td className="text-stone-600">{d.cmds} 条(route / fib / bgp_paths / neighbor ×2 / detail)</Td>
                <Td><button className="text-stone-300 hover:text-rose-600"><Trash2 size={15} /></button></Td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </Panel>
  );
}

function SnapshotStage({ kind }) {
  const snap = SNAPSHOTS.find((s) => s.kind === kind);
  const [derived, setDerived] = useState(kind === "pre"
    ? [{ family: "bgp_neighbor_received", matched: "4018/4021", filled: "communities localpref med" }] : []);
  const [enr, setEnr] = useState("idle");
  const [fam, setFam] = useState("bgp_paths");
  const runEnrich = () => {
    setEnr("run");
    setTimeout(() => {
      setDerived((d) => [...d, { family: fam, matched: "8210/8412", filled: "communities localpref med" }]);
      setEnr("idle");
    }, 700);
  };
  return (
    <Panel title={`${kind.toUpperCase()} 快照 · ${snap.label}`} sub={`采集于 ${snap.taken} · ${snap.records.toLocaleString()} 条记录已入库`}>
      <div className="mb-4 flex items-center gap-3 rounded-lg border border-dashed border-stone-300 bg-white px-5 py-4">
        <Upload size={18} className="text-teal-700" />
        <div className="flex-1 text-sm text-stone-600">拖入采集文件(每设备一个 .txt,marker 格式),可多次追加上传;detail 采集也可在第 ④ 阶段定向导入本快照</div>
        <button className="rounded-md border border-stone-300 px-3 py-1.5 text-sm font-medium text-stone-700 hover:bg-stone-50">选择文件</button>
      </div>

      <Card className="mb-4 p-4">
        <div className="mb-2 flex items-center gap-2">
          <Sparkles size={15} className="text-teal-700" />
          <span className="f-disp text-sm font-semibold text-stone-900">派生快照(Enrich)</span>
          <span className="text-xs text-stone-400">以 prefix+nexthop 匹配本快照 detail 路径,补空填充属性 → 生成新快照</span>
        </div>
        {derived.map((d, i) => (
          <div key={i} className="mb-1.5 flex items-center gap-2 rounded-md bg-teal-50 px-3 py-2">
            <Chip c="bg-teal-100 text-teal-800">enriched</Chip>
            <span className="f-mono text-xs text-stone-700">{snap.label} · {d.family}</span>
            <span className="f-mono ml-auto text-xs text-stone-500">命中 {d.matched} · 填充 {d.filled}</span>
            <button className="text-stone-300 hover:text-rose-600"><Trash2 size={13} /></button>
          </div>
        ))}
        <div className="mt-2 flex items-center gap-2">
          <select value={fam} onChange={(e) => setFam(e.target.value)}
            className="f-mono rounded-md border border-stone-300 bg-white px-2 py-1.5 text-xs">
            <option value="bgp_paths">bgp_paths</option>
            <option value="bgp_neighbor_received">bgp_neighbor_received</option>
          </select>
          <button onClick={runEnrich} className="rounded-md bg-teal-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-teal-800">
            {enr === "run" ? <Loader2 size={13} className="animate-spin" /> : "Enrich → 新派生快照"}
          </button>
        </div>
      </Card>

      <Card>
        <div className="border-b border-stone-100 px-4 py-2.5 text-xs font-semibold text-stone-500">覆盖率 · 每设备每命令实例一行,0 条与缺失是两回事;detail 命令对比时聚合为一个单元</div>
        <table className="w-full">
          <tbody>
            {COVERAGE.map((r, i) => (
              <tr key={i} className="border-b border-stone-50 last:border-0">
                <Td mono className="w-24 text-stone-500">{r.device}</Td>
                <Td mono className="text-stone-800">{r.command}</Td>
                <Td mono className="w-44 text-stone-400">{r.family}</Td>
                <Td mono className="w-20 text-right">{r.st === "missing" ? "—" : r.n.toLocaleString()}</Td>
                <Td className="w-24">
                  {r.st === "ok"
                    ? <Chip c="bg-teal-50 text-teal-700">ok</Chip>
                    : <Chip c="bg-rose-50 text-rose-700">缺失</Chip>}
                </Td>
              </tr>
            ))}
            <tr className="border-b border-stone-50 last:border-0">
              <Td mono className="w-24 text-stone-500">router1</Td>
              <Td mono className="text-stone-800">detail 导入 · show ip bgp x.x.x.x ×128</Td>
              <Td mono className="w-44 text-stone-400">bgp_prefix_detail</Td>
              <Td mono className="w-20 text-right">396</Td>
              <Td className="w-24"><Chip c="bg-teal-50 text-teal-700">ok</Chip></Td>
            </tr>
          </tbody>
        </table>
      </Card>
    </Panel>
  );
}

function DetailStage() {
  const [policy, setPolicy] = useState("random");
  const [genState, setGen] = useState("done");
  const Radio = ({ v, label, children }) => (
    <label className={`flex cursor-pointer items-start gap-2.5 rounded-lg border px-4 py-3 ${policy === v ? "border-teal-600 bg-teal-50" : "border-stone-200 bg-white"}`}>
      <input type="radio" checked={policy === v} onChange={() => setPolicy(v)} className="mt-1 accent-teal-700" />
      <span><span className="block text-sm font-medium text-stone-800">{label}</span>
        <span className="mt-0.5 block text-xs text-stone-500">{children}</span></span>
    </label>
  );
  return (
    <Panel title="DETAIL 前缀清单" sub="从 PRE 快照生成 show ip bgp x.x.x.x 命令清单;pre 与 post 必须补跑同一份">
      <div className="mb-4 grid grid-cols-3 gap-3">
        <Radio v="all" label="全部前缀">来源族的每个前缀都生成</Radio>
        <Radio v="mask" label="按掩码过滤">
          运算符 <span className="f-mono">ge</span> · 长度 <input className="f-mono w-10 rounded border border-stone-300 px-1 text-center" defaultValue="24" />
        </Radio>
        <Radio v="random" label="随机抽样">
          N=<input className="f-mono w-14 rounded border border-stone-300 px-1 text-center" defaultValue="128" />
          · seed=<input className="f-mono w-14 rounded border border-stone-300 px-1 text-center" defaultValue="42" />(落库,可复现)
        </Radio>
      </div>
      <div className="mb-4 flex items-center gap-3">
        <span className="text-sm text-stone-500">来源:</span>
        <select className="f-mono rounded-md border border-stone-300 bg-white px-2 py-1.5 text-xs">
          <option>snapshot #1 (pre) · bgp_paths</option>
          <option>snapshot #1 (pre) · neighbor 10.1.1.1 received</option>
        </select>
        <button onClick={() => { setGen("run"); setTimeout(() => setGen("done"), 500); }}
          className="rounded-md bg-teal-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-800">生成清单</button>
      </div>
      {genState === "run" && <div className="flex items-center gap-2 text-sm text-stone-500"><Loader2 size={15} className="animate-spin" />生成中…</div>}
      {genState === "done" && (
        <Card className="p-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm text-stone-700">已生成 <span className="f-mono font-semibold">128</span> 条,写入 detail_plan(覆盖式)</span>
            <span className="flex gap-2">
              <button className="flex items-center gap-1 rounded-md border border-stone-300 px-2.5 py-1 text-xs font-medium hover:bg-stone-50"><Download size={13} />EOS 命令清单</button>
              <button className="flex items-center gap-1 rounded-md border border-stone-300 px-2.5 py-1 text-xs font-medium hover:bg-stone-50"><Download size={13} />XR 命令清单</button>
            </span>
          </div>
          <pre className="f-mono rounded bg-stone-50 p-3 text-xs leading-5 text-stone-600">{`show ip bgp 10.50.1.0/24 | json
show ip bgp 10.99.0.0/16 | json
show bgp vpnv4 unicast rd 65000:100 10.50.1.0/24
… 其余 125 条`}</pre>
        </Card>
      )}

      <div className="mt-5">
        <h3 className="f-disp mb-2 text-sm font-semibold text-stone-900">导入 detail 采集</h3>
        <div className="flex items-center gap-3 rounded-lg border border-dashed border-stone-300 bg-white px-5 py-4">
          <Upload size={18} className="text-teal-700" />
          <div className="flex-1 text-sm text-stone-600">
            很多条命令一个文件(补跑清单的完整输出),定向导入到目标快照
            <div className="f-mono mt-0.5 text-xs text-stone-400">对比时全部 detail 聚合为一个单元,不按单命令拆分</div>
          </div>
          <span className="text-xs text-stone-400">导入到</span>
          <select className="f-mono rounded-md border border-stone-300 bg-white px-2 py-1.5 text-xs">
            <option>#1 PRE · pre-change</option>
            <option>#2 POST · post-change</option>
          </select>
          <button className="rounded-md bg-teal-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-800">选择文件</button>
        </div>
        <div className="mt-2 flex items-center gap-2 text-xs text-stone-500">
          <Check size={13} className="text-teal-700" />已导入 396 条 detail 记录 → <span className="f-mono">#1 PRE</span>(在 PRE 快照页 coverage 中可见,可随后 Enrich)
        </div>
      </div>
    </Panel>
  );
}

function CompareStage({ onDone }) {
  const [mode, setMode] = useState("auto");   // auto: pre→post | custom: 任选两个实例
  const [st, setSt] = useState("done");
  const [flt, setFlt] = useState({ device: "", family: "", change: "", afi: "", q: "" });
  const [ign, setIgn] = useState([]);
  const ignSet = useMemo(() => new Set(ign.flatMap((l) => IGN_CHIPS.find((c) => c.label === l).fields)), [ign]);
  const base = mode === "auto" ? FINDINGS : ADHOC.findings;

  /* 读时投影:changed 事实剔除被忽略字段,剔空则整条隐藏(对应 ignore_fields 参数语义) */
  const { all, rows, sup } = useMemo(() => {
    let sup = 0; const all = [];
    for (const f of base) {
      if (f.change === "changed" && ignSet.size) {
        const eff = f.fields.filter((x) => !ignSet.has(x));
        if (!eff.length) { sup++; continue; }
        const pick = (d) => d && Object.fromEntries(Object.entries(d).filter(([k]) => eff.includes(k)));
        all.push({ ...f, fields: eff, before: pick(f.before), after: pick(f.after) });
      } else all.push(f);
    }
    const rows = all.filter((f) =>
      (!flt.device || f.device === flt.device) &&
      (!flt.family || f.family === flt.family) &&
      (!flt.change || f.change === flt.change) &&
      (!flt.afi || f.identity.afi_safi === flt.afi) &&
      (!flt.q || JSON.stringify(f).toLowerCase().includes(flt.q.toLowerCase())));
    return { all, rows, sup };
  }, [base, flt, ignSet]);

  const counts = useMemo(() => {
    const c = { added: 0, removed: 0, changed: 0, missing_command: 0 };
    all.forEach((f) => { c[f.change] = (c[f.change] || 0) + 1; });
    return c;
  }, [all]);
  const chgLabel = (ch) =>
    mode === "custom" ? ({ removed: "仅 A", added: "仅 B", changed: "不同" }[ch] || CHG[ch].label) : CHG[ch].label;
  const instOf = (f) => f.identity.neighbor ? `nei ${f.identity.neighbor}`
    : f.family === "bgp_prefix_detail" ? f.identity.prefix
    : f.identity.vrf !== undefined ? `vrf ${f.identity.vrf || "(global)"}` : "";

  const Sel = ({ k, opts, ph }) => (
    <select value={flt[k]} onChange={(e) => setFlt({ ...flt, [k]: e.target.value })}
      className="f-mono rounded-md border border-stone-300 bg-white px-2 py-1.5 text-xs text-stone-700">
      <option value="">{ph}</option>{opts.map((o) => <option key={o} value={o}>{o}</option>)}
    </select>
  );
  const run = () => { setSt("run"); setTimeout(() => { setSt("done"); onDone(); }, 700); };

  return (
    <Panel title="对比" sub="对快照库的现算 · 事实只有 added / removed / changed,判断留给你"
      right={<span className="f-mono rounded bg-stone-100 px-2 py-1 text-xs text-stone-500">rules 3.0</span>}>
      <div className="mb-4 flex w-fit gap-1 rounded-lg bg-stone-200 p-0.5">
        {[["auto", "自动配对 pre → post"], ["custom", "自定义配对 · 任选两个实例"]].map(([m, l]) => (
          <button key={m} onClick={() => { setMode(m); setSt("done"); setFlt({ device: "", family: "", change: "", afi: "", q: "" }); }}
            className={`rounded-md px-3 py-1.5 text-xs font-medium ${mode === m ? "bg-white text-stone-900 shadow-sm" : "text-stone-500"}`}>{l}</button>
        ))}
      </div>

      {mode === "auto" ? (
        <div className="mb-4">
          <div className="flex items-center gap-2">
            <select className="f-mono rounded-md border border-stone-300 bg-white px-2 py-1.5 text-xs">
              <option>#1 pre-change · 07-10 21:40</option>
              <option>#3 pre-change · bgp_paths enriched(源 #1)</option>
            </select>
            <ArrowRight size={14} className="text-stone-400" />
            <select className="f-mono rounded-md border border-stone-300 bg-white px-2 py-1.5 text-xs">
              <option>#2 post-change · 07-11 01:15</option>
              <option>#4 post-change · bgp_paths enriched(源 #2)</option>
            </select>
            <button onClick={run} className="ml-2 rounded-md bg-teal-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-800">
              {st === "run" ? <Loader2 size={15} className="animate-spin" /> : "运行对比"}
            </button>
            <span className="text-xs text-stone-400">按 (device, family, params) 逐实例配对,同族不同实例各比各的</span>
          </div>
          <div className="f-mono mt-1.5 text-xs text-stone-400">
            派生快照与普通快照同权可选;单侧 enriched 时,被填充字段将自动预选进"忽略属性"(suggested_ignore_fields,可取消)
          </div>
        </div>
      ) : (
        <div className="mb-4 space-y-2">
          {[["实例 A", ADHOC.a], ["实例 B", ADHOC.b]].map(([lab, val]) => (
            <div key={lab} className="flex items-center gap-2">
              <span className="f-mono w-12 text-xs text-stone-400">{lab}</span>
              <select className="f-mono min-w-96 rounded-md border border-stone-300 bg-white px-2 py-1.5 text-xs">
                <option>{val}</option>
                <option>#2 post · router1 · received · nei 10.1.1.1</option>
                <option>#1 pre · router2 · bgp_paths · vpnv4 rd 65000:100</option>
              </select>
            </div>
          ))}
          <div className="flex items-center gap-3">
            <button onClick={run} className="rounded-md bg-teal-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-800">
              {st === "run" ? <Loader2 size={15} className="animate-spin" /> : "运行对比"}
            </button>
            {st === "done" && (
              <span className="rounded-md border border-teal-200 bg-teal-50 px-3 py-1.5 text-xs text-teal-800">对齐说明:{ADHOC.align}</span>
            )}
          </div>
        </div>
      )}

      {st === "done" && (<>
        <div className="mb-3 flex gap-2.5">
          {[["added", "text-emerald-700 bg-emerald-50"], ["removed", "text-rose-700 bg-rose-50"],
            ["changed", "text-amber-700 bg-amber-50"], ["missing_command", "text-stone-600 bg-stone-100"]]
            .filter(([k]) => counts[k] > 0 || mode === "auto")
            .map(([k, c]) => (
              <button key={k} onClick={() => setFlt({ ...flt, change: flt.change === k ? "" : k })}
                className={`rounded-lg px-3.5 py-2 text-left ${c} ${flt.change === k ? "ring-1 ring-stone-400" : ""}`}>
                <span className="f-disp block text-xl font-semibold leading-6">{counts[k]}</span>
                <span className="f-mono text-xs opacity-70">{chgLabel(k)}</span>
              </button>
            ))}
          <div className="ml-auto flex items-center gap-2">
            <Sel k="device" ph="device" opts={["router1", "router2"]} />
            <Sel k="family" ph="family" opts={["bgp_paths", "route_table", "forwarding_table", "bgp_neighbor_received", "bgp_neighbor_advertised", "coverage"]} />
            <Sel k="afi" ph="afi_safi" opts={["ipv4_unicast", "vpnv4_unicast"]} />
            <span className="relative">
              <Search size={13} className="absolute left-2 top-2 text-stone-400" />
              <input value={flt.q} onChange={(e) => setFlt({ ...flt, q: e.target.value })} placeholder="prefix / rd / peer …"
                className="f-mono w-44 rounded-md border border-stone-300 py-1.5 pl-7 pr-2 text-xs" />
            </span>
          </div>
        </div>

        <div className="mb-3 flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-stone-400">忽略属性:</span>
          {IGN_CHIPS.map((c) => {
            const on = ign.includes(c.label);
            return (
              <button key={c.label} onClick={() => setIgn(on ? ign.filter((x) => x !== c.label) : [...ign, c.label])}
                className={`f-mono flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs
                  ${on ? "border-teal-600 bg-teal-50 text-teal-800" : "border-stone-300 bg-white text-stone-500 hover:border-stone-400"}`}>
                {on && <X size={11} />}{c.label}
              </button>
            );
          })}
          {sup > 0 && <span className="f-mono ml-1 text-xs text-stone-400">已因忽略隐藏 {sup} 条 changed</span>}
        </div>

        <Card>
          <div className="flex items-center justify-between border-b border-stone-100 px-4 py-2 text-xs text-stone-400">
            <span>{rows.length} / {all.length} 条事实(产品中为服务端过滤 + 虚拟滚动;忽略是读时投影,不重算)</span>
            <span className="f-mono">运行工件 {mode === "auto" ? "compare_MToy" : "compare_adhoc_9f2"}.jsonl.gz · rules 3.3 · 导出与 AI 共用此数据源</span>
          </div>
          <table className="w-full">
            <thead className="border-b border-stone-100"><tr>
              <Th>变化</Th><Th>设备</Th><Th>族 / 实例</Th><Th>对象</Th>
              <Th>{mode === "auto" ? "变更前" : "实例 A"}</Th>
              <Th>{mode === "auto" ? "变更后" : "实例 B"}</Th>
            </tr></thead>
            <tbody>
              {rows.map((f, i) => (
                <tr key={i} className={`border-b border-l-2 border-stone-50 ${CHG[f.change].bar} last:border-b-0`}>
                  <Td className="w-20"><Chip c={CHG[f.change].chip}>{chgLabel(f.change)}</Chip></Td>
                  <Td mono className="w-20 text-stone-500">{f.device}</Td>
                  <Td mono className="w-44 text-stone-500">{f.family}
                    {instOf(f) && <div className="text-stone-300">{instOf(f)}</div>}
                  </Td>
                  <Td mono className="text-stone-800">
                    {Object.entries(f.identity).filter(([, v]) => v !== "").map(([k, v]) => (
                      <div key={k}><span className="text-stone-400">{k}=</span>{v}</div>))}
                  </Td>
                  <Td><KV d={f.before} hl={f.fields} /></Td>
                  <Td><KV d={f.after} hl={f.fields} /></Td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </>)}
    </Panel>
  );
}

function ExportStage() {
  const [ai, setAi] = useState("idle");
  return (
    <Panel title="导出与分析" sub="导出文件是留档;findings 不落库,项目删除后只有这些文件留下来">
      <div className="mb-5 grid grid-cols-3 gap-3">
        {[["report.html", "自包含,可附变更单"], ["findings.csv", "UTF-8 BOM,Excel 直开"], ["findings.xlsx", "每族一个 sheet"]].map(([f, d]) => (
          <Card key={f} className="flex items-center gap-3 p-4">
            <FileDown size={18} className="text-teal-700" />
            <span className="flex-1"><span className="f-mono block text-sm font-medium text-stone-800">{f}</span>
              <span className="text-xs text-stone-500">{d}</span></span>
            <button className="rounded-md border border-stone-300 px-2.5 py-1 text-xs font-medium hover:bg-stone-50">下载</button>
          </Card>
        ))}
      </div>
      <Card className="p-5">
        <div className="mb-1 flex items-center gap-2">
          <Sparkles size={16} className="text-teal-700" />
          <span className="f-disp text-sm font-semibold text-stone-900">AI 分析</span>
          <span className="f-mono rounded bg-stone-100 px-1.5 py-0.5 text-xs text-stone-500">V2 · 消费 bundle.json</span>
        </div>
        <p className="mb-3 text-xs leading-5 text-stone-500">
          分析模块只读机器可读导出物 <span className="f-mono">GET /compares/{"{cid}"}/bundle.json</span>(事实 + 摘要 + 覆盖率),
          不触碰对比引擎。分析是观点,事实才留档——分析文本不写入任何导出文件。
        </p>
        {ai === "idle" && <button onClick={() => { setAi("run"); setTimeout(() => setAi("done"), 900); }}
          className="rounded-md bg-teal-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-800">对本次对比运行分析</button>}
        {ai === "run" && <div className="flex items-center gap-2 text-sm text-stone-500"><Loader2 size={15} className="animate-spin" />正在阅读 18 条事实…</div>}
        {ai === "done" && (
          <div className="rounded-lg bg-stone-50 p-4 text-sm leading-6 text-stone-700">
            {AI_TEXT.map((t, i) => <p key={i} className="mb-1.5 last:mb-0">{t}</p>)}
            <p className="f-mono mt-3 text-xs text-stone-400">bundle_schema 1 · rules 3.0 · 以上为示范环境的演示文本</p>
          </div>
        )}
      </Card>
      <div className="mt-5 flex items-center justify-between rounded-lg border border-rose-200 bg-rose-50 px-4 py-3">
        <span className="text-sm text-rose-800">导出完成后可删除项目:将清空其全部快照数据,导出文件不受影响。</span>
        <button className="rounded-md border border-rose-300 px-3 py-1.5 text-sm font-medium text-rose-700 hover:bg-rose-100">删除项目…</button>
      </div>
    </Panel>
  );
}

/* ── 页面骨架 ─────────────────────────────────────────────── */
function ProjectsPage({ open }) {
  return (
    <Panel title="项目" sub="一个项目 = 一次变更验证:设备清单、pre/post 快照、对比与导出"
      right={<button className="flex items-center gap-1.5 rounded-md bg-teal-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-800"><Plus size={15} />新建项目</button>}>
      <Card>
        <table className="w-full">
          <thead className="border-b border-stone-100"><tr><Th>项目</Th><Th>状态</Th><Th>设备</Th><Th>快照</Th><Th>创建</Th><Th /></tr></thead>
          <tbody>
            {PROJECTS.map((p) => (
              <tr key={p.id} onClick={() => open(p)} className="cursor-pointer border-b border-stone-50 last:border-0 hover:bg-stone-50">
                <Td className="font-medium text-stone-900">{p.name}</Td>
                <Td><Chip c={p.status === "进行中" ? "bg-teal-50 text-teal-700" : "bg-stone-100 text-stone-500"}>{p.status}</Chip></Td>
                <Td mono>{p.devices}</Td><Td mono className="text-stone-500">{p.snaps}</Td>
                <Td mono className="text-stone-400">{p.created}</Td>
                <Td><ChevronRight size={15} className="text-stone-300" /></Td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </Panel>
  );
}

export default function App() {
  const [proj, setProj] = useState(null);
  const [stage, setStage] = useState("compare");
  const [done, setDone] = useState(["devices", "pre", "detail", "post"]);
  return (
    <div className="min-h-screen bg-stone-100 text-stone-900" style={{ fontFamily: "Inter, system-ui, sans-serif" }}>
      <style>{FONT}</style>
      <header className="flex items-center gap-4 border-b border-stone-200 bg-white px-6 py-3">
        <span className="f-disp flex items-center gap-2 text-base font-bold tracking-tight">
          <Terminal size={17} className="text-teal-700" />netval
        </span>
        {proj && (<>
          <ChevronRight size={14} className="text-stone-300" />
          <button onClick={() => setProj(null)} className="text-sm text-stone-500 hover:text-teal-700">项目</button>
          <ChevronRight size={14} className="text-stone-300" />
          <span className="text-sm font-medium">{proj.name}</span>
        </>)}
        <span className="f-mono ml-auto text-xs text-stone-400">engine rules 3.0</span>
      </header>
      {!proj ? (
        <ProjectsPage open={(p) => { setProj(p); setStage("devices"); }} />
      ) : (
        <div className="flex" style={{ minHeight: "calc(100vh - 53px)" }}>
          <StageRail stage={stage} setStage={setStage} done={done} />
          <main className="min-w-0 flex-1">
            {stage === "devices" && <DevicesStage />}
            {stage === "pre" && <SnapshotStage kind="pre" />}
            {stage === "detail" && <DetailStage />}
            {stage === "post" && <SnapshotStage kind="post" />}
            {stage === "compare" && <CompareStage onDone={() => setDone((d) => [...new Set([...d, "compare"])])} />}
            {stage === "export" && <ExportStage />}
          </main>
        </div>
      )}
    </div>
  );
}
