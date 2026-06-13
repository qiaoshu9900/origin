import React, { useMemo, useRef, useState } from "react";
import * as XLSX from "xlsx";

/* ============================================================
   核心数据模型(唯一真相源)
   Block(任意深度域树) / Device(含 breakouts) / Link(规则生成)
   图 / BOM / Patching 表全部派生,不允许手画连线
   ============================================================ */

let _seq = 1;
const uid = (p = "X") => `${p}${_seq++}`;

/* ---------- 设备型号库(端口范围 + 可拆分能力 bo) ---------- */
const MODELS = {
  "DCS-7280CR3-32P4": {
    vendor: "Arista", prefix: "Et",
    ports: [
      { from: 1, to: 32, speed: 100, type: "QSFP28", bo: [25] },
      { from: 33, to: 36, speed: 400, type: "QSFP-DD", bo: [100] },
    ],
  },
  "N9K-C9336C-FX2": {
    vendor: "Cisco", prefix: "Eth1/",
    ports: [{ from: 1, to: 36, speed: 100, type: "QSFP28", bo: [25] }],
  },
  "N9K-C93180YC-FX3": {
    vendor: "Cisco", prefix: "Eth1/",
    ports: [
      { from: 1, to: 48, speed: 25, type: "SFP28" },
      { from: 49, to: 54, speed: 100, type: "QSFP28", bo: [25] },
    ],
  },
  "N9K-C93108TC-FX3": {
    vendor: "Cisco", prefix: "Eth1/",
    ports: [
      { from: 1, to: 48, speed: 10, type: "RJ45" },
      { from: 49, to: 54, speed: 100, type: "QSFP28", bo: [25] },
    ],
  },
  "DCS-7050SX3-48YC8": {
    vendor: "Arista", prefix: "Et",
    ports: [
      { from: 1, to: 48, speed: 25, type: "SFP28" },
      { from: 49, to: 56, speed: 100, type: "QSFP28", bo: [25] },
    ],
  },
};

const SPEEDS = [400, 100, 40, 25, 10];
const SPEED_COLOR = { 400: "#E4572E", 100: "#F2A33C", 40: "#9B5DE5", 25: "#3FA7D6", 10: "#7BC950" };
const TYPES = {
  core: { label: "DC Core", color: "#F2762E" },
  external: { label: "External", color: "#3FA7D6" },
  compute: { label: "Compute", color: "#9B5DE5" },
  backup: { label: "Backup", color: "#43AA8B" },
  oob: { label: "OOB", color: "#8D99AE" },
  dwdm: { label: "DWDM", color: "#E05780" },
  sub: { label: "子域", color: "#5C7AA3" },
};
const TOP_TYPES = ["core", "external", "compute", "backup", "oob", "dwdm"];

/* ---------- 端口展开 ---------- */
function expandNative(modelKey) {
  const m = MODELS[modelKey];
  if (!m) return [];
  const out = [];
  m.ports.forEach((r) => {
    for (let n = r.from; n <= r.to; n++)
      out.push({ name: `${m.prefix}${n}`, speed: r.speed, type: r.type, bo: r.bo || null });
  });
  return out;
}

// 设备的"有效端口"= 原生端口,已拆分的父口替换为 4 个子口
function effectivePorts(dev, boOverride) {
  const bo = boOverride !== undefined ? boOverride || {} : dev.breakouts || {};
  const out = [];
  expandNative(dev.model).forEach((p) => {
    const cs = bo[p.name];
    if (cs) {
      for (let k = 1; k <= 4; k++)
        out.push({ name: `${p.name}/${k}`, speed: cs, type: p.type, parent: p.name });
    } else out.push(p);
  });
  return out;
}

function usedPortsOf(devId, links) {
  const s = new Set();
  links.forEach((l) => {
    if (l.aDev === devId) s.add(l.aPort);
    if (l.bDev === devId) s.add(l.bPort);
  });
  return s;
}

function parentBO(dev, port) {
  const bo = dev?.breakouts;
  if (!bo) return null;
  return Object.keys(bo).find((p) => port.startsWith(p + "/")) || null;
}

function supportsSpeed(modelKey, speed, allowBO) {
  const m = MODELS[modelKey];
  if (!m) return false;
  return m.ports.some((r) => r.speed === speed || (allowBO && r.bo && r.bo.includes(speed)));
}

/* ---------- 端口自动分配(含自动 breakout) ----------
   desc=true:从高位口往下(peer/uplink)  false:低位往上(downlink)
   bo:工作中的 breakout 状态副本 {devId:{portName:childSpeed}}        */
function allocPort(dev, speed, desc, links, bo, allowBO) {
  const used = usedPortsOf(dev.id, links);
  const eff = effectivePorts(dev, bo[dev.id] !== undefined ? bo[dev.id] : dev.breakouts);
  const list = desc ? [...eff].reverse() : eff;
  const hit = list.find((q) => q.speed === speed && !used.has(q.name));
  if (hit) return hit;
  if (allowBO) {
    const nat = expandNative(dev.model);
    const cands = desc ? [...nat].reverse() : nat;
    const cur = bo[dev.id] !== undefined ? bo[dev.id] : dev.breakouts || {};
    const c = cands.find(
      (q) => q.bo && q.bo.includes(speed) && !used.has(q.name) && !cur[q.name]
    );
    if (c) {
      bo[dev.id] = { ...cur, [c.name]: speed };
      return { name: `${c.name}/1`, speed, type: c.type, parent: c.name };
    }
  }
  return null;
}

/* ---------- 连线生成器 ---------- */
function buildGroupLinks({ kind, devsA, devsB, pattern, per, speed, groupId, tag, existing, descA, descB, allowBO }) {
  const work = [...existing];
  const added = [];
  const bo = {};
  const pairs = [];

  if (kind === "internal") {
    const ds = devsA;
    if (ds.length < 2) return { error: "块内互联至少需要 2 台设备" };
    if (pattern === "mesh") {
      for (let i = 0; i < ds.length; i++)
        for (let j = i + 1; j < ds.length; j++) pairs.push([ds[i], ds[j]]);
    } else {
      const n = ds.length;
      for (let i = 0; i < n; i++) {
        if (n === 2 && i === 1) break;
        pairs.push([ds[i], ds[(i + 1) % n]]);
      }
    }
  } else {
    if (!devsA.length || !devsB.length) return { error: "两侧都需要至少 1 台设备" };
    for (const a of devsA) for (const b of devsB) pairs.push([a, b]);
  }

  const fail = (dev) => {
    if (!supportsSpeed(dev.model, speed, allowBO)) {
      const m = MODELS[dev.model];
      const nat = [...new Set(m.ports.map((r) => r.speed))].join("/");
      const bos = [...new Set(m.ports.flatMap((r) => r.bo || []))];
      return `${dev.name} 的型号 ${dev.model} 不支持 ${speed}G(原生 ${nat}G${bos.length ? ",可拆分出 " + bos.join("/") + "G" : ""})`;
    }
    return `${dev.name} 的 ${speed}G 端口已用尽(可在设备详情中检查余量)`;
  };

  for (const [a, b] of pairs) {
    for (let k = 0; k < per; k++) {
      const pa = allocPort(a, speed, descA, work, bo, allowBO);
      if (!pa) return { error: fail(a) };
      const pb = allocPort(b, speed, descB, work, bo, allowBO);
      if (!pb) return { error: fail(b) };
      const link = {
        id: uid("L"), groupId,
        aDev: a.id, aPort: pa.name, aType: pa.type,
        bDev: b.id, bPort: pb.name, bType: pb.type,
        speed, tag,
      };
      work.push(link);
      added.push(link);
    }
  }
  return { added, bo };
}

/* ---------- 种子数据:三层域树 + breakout 演示 ---------- */
function buildSeed() {
  const blocks = [
    { id: "B1", name: "DC-CORE", type: "core", parentId: null, x: 110, y: 215 },
    { id: "B2", name: "EXTERNAL", type: "external", parentId: null, x: 560, y: 55 },
    { id: "B21", name: "INTERNET", type: "sub", parentId: "B2", x: 0, y: 0 },
    { id: "B211", name: "INET-ACCESS", type: "sub", parentId: "B21", x: 0, y: 0 },
    { id: "B22", name: "LEASE-LINE", type: "sub", parentId: "B2", x: 0, y: 0 },
    { id: "B3", name: "COMPUTE", type: "compute", parentId: null, x: 560, y: 340 },
    { id: "B4", name: "OOB", type: "oob", parentId: null, x: 110, y: 430 },
  ];
  const blockLinks = [
    { id: "BL1", a: "B1", b: "B2" },
    { id: "BL2", a: "B1", b: "B3" },
    { id: "BL3", a: "B1", b: "B4" },
  ];
  const devices = [];
  const mk = (blockId, model, n, base) => {
    for (let i = 1; i <= n; i++)
      devices.push({ id: uid("D"), blockId, model, name: `${base}-${String(i).padStart(2, "0")}`, breakouts: {} });
  };
  mk("B1", "DCS-7280CR3-32P4", 4, "DC-CORE");
  mk("B2", "N9K-C9336C-FX2", 2, "EXT-RTR");
  mk("B21", "N9K-C9336C-FX2", 2, "INET-DIST");
  mk("B211", "N9K-C93180YC-FX3", 2, "INET-ACC");
  mk("B3", "N9K-C93180YC-FX3", 2, "COMPUTE-LEAF");

  const dvs = (b) => devices.filter((d) => d.blockId === b);
  const links = [];
  const groups = [];
  const apply = (r, g) => {
    links.push(...r.added);
    devices.forEach((d) => { if (r.bo[d.id]) d.breakouts = r.bo[d.id]; });
    groups.push(g);
  };

  apply(
    buildGroupLinks({ kind: "internal", devsA: dvs("B1"), pattern: "mesh", per: 1, speed: 400, groupId: "G1", tag: "CORE peer", existing: links, descA: true, descB: true, allowBO: false }),
    { id: "G1", blockId: "B1", label: "DC-CORE 域内 · full-mesh · 1×400G" }
  );
  apply(
    buildGroupLinks({ kind: "cross", devsA: dvs("B2"), devsB: dvs("B1"), per: 1, speed: 100, groupId: "G2", tag: "EXTERNAL uplink", existing: links, descA: true, descB: false, allowBO: false }),
    { id: "G2", blockId: "B2", label: "EXTERNAL → DC-CORE · 每对 1×100G" }
  );
  apply(
    buildGroupLinks({ kind: "cross", devsA: dvs("B21"), devsB: dvs("B2"), per: 1, speed: 100, groupId: "G3", tag: "INTERNET uplink", existing: links, descA: true, descB: false, allowBO: false }),
    { id: "G3", blockId: "B21", label: "INTERNET → EXTERNAL(父域)· 每对 1×100G" }
  );
  apply(
    buildGroupLinks({ kind: "cross", devsA: dvs("B211"), devsB: dvs("B21"), per: 2, speed: 25, groupId: "G4", tag: "ACCESS uplink", existing: links, descA: true, descB: false, allowBO: true }),
    { id: "G4", blockId: "B211", label: "INET-ACCESS → INTERNET(父域)· 每对 2×25G(对端自动 breakout)" }
  );
  apply(
    buildGroupLinks({ kind: "cross", devsA: dvs("B3"), devsB: dvs("B1"), per: 1, speed: 100, groupId: "G5", tag: "COMPUTE uplink", existing: links, descA: true, descB: false, allowBO: false }),
    { id: "G5", blockId: "B3", label: "COMPUTE → DC-CORE · 每对 1×100G" }
  );

  return { blocks, blockLinks, devices, links, groups };
}
const SEED = buildSeed();

/* ---------- 工具 ---------- */
const spread = (n, w = 880, x0 = 60) =>
  n <= 1 ? [x0 + w / 2] : Array.from({ length: n }, (_, i) => x0 + (w / (n - 1)) * i);
const pairKey = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);

const CSS = `
.fp-app{font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:#ECEFF3;min-height:100vh;color:#1C2B3A;}
.fp-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}
.fp-hdr{background:#10243F;color:#fff;padding:14px 22px;display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
.fp-hdr h1{font-size:15px;margin:0;letter-spacing:2px;font-family:ui-monospace,Menlo,monospace;}
.fp-hdr small{color:#8FA6BD;font-size:11px;display:block;margin-top:2px;}
.fp-tabs{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap;}
.fp-tabs button{background:transparent;border:none;color:#A9BCD0;padding:8px 12px;font-size:13px;cursor:pointer;border-bottom:2px solid transparent;}
.fp-tabs button.on{color:#fff;border-bottom-color:#F2762E;}
.fp-body{padding:16px 22px;display:flex;gap:14px;align-items:flex-start;}
.fp-panel{background:#fff;border:1px solid #D8DEE6;border-radius:10px;padding:14px;}
.fp-panel h3{margin:0 0 10px;font-size:12px;letter-spacing:1.5px;color:#5A6B7E;text-transform:uppercase;}
.fp-btn{background:#fff;border:1px solid #C4CDD8;border-radius:7px;padding:6px 12px;font-size:12.5px;cursor:pointer;color:#1C2B3A;}
.fp-btn:hover{border-color:#F2762E;color:#C2530F;}
.fp-btn.pri{background:#F2762E;border-color:#F2762E;color:#fff;font-weight:600;}
.fp-btn.pri:hover{background:#D9621F;color:#fff;}
.fp-btn.danger{color:#B3392B;}
.fp-btn.sm{padding:2px 8px;font-size:11.5px;}
.fp-input,.fp-sel{border:1px solid #C4CDD8;border-radius:7px;padding:6px 8px;font-size:12.5px;background:#fff;color:#1C2B3A;}
.fp-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
.fp-list-item{display:flex;justify-content:space-between;align-items:center;padding:6px 9px;border-radius:7px;cursor:pointer;font-size:13px;gap:6px;}
.fp-list-item:hover{background:#F1F4F8;}
.fp-list-item.on{background:#FDEBDD;color:#A14A12;font-weight:600;}
.fp-table{border-collapse:collapse;width:100%;font-size:12px;}
.fp-table th{background:#10243F;color:#D7E1EC;padding:7px 9px;text-align:left;font-weight:600;white-space:nowrap;position:sticky;top:0;}
.fp-table td{border-bottom:1px solid #E4E9EF;padding:5px 9px;white-space:nowrap;}
.fp-table tr:hover td{background:#F6F8FB;}
.fp-chip{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:600;}
.fp-hint{font-size:11.5px;color:#7A8A9B;margin-top:8px;line-height:1.6;}
.fp-group{border:1px solid #E0E6ED;border-radius:8px;padding:8px 10px;margin-bottom:8px;font-size:12.5px;display:flex;justify-content:space-between;align-items:center;gap:8px;}
.fp-label{font-size:11px;color:#5A6B7E;display:block;margin-bottom:3px;}
.fp-bar{height:5px;border-radius:3px;background:#E7EBF0;overflow:hidden;}
.fp-bar i{display:block;height:100%;background:#F2762E;border-radius:3px;}
`;

/* ============================================================ */
export default function NetworkDesigner() {
  const [blocks, setBlocks] = useState(SEED.blocks);
  const [blockLinks, setBlockLinks] = useState(SEED.blockLinks);
  const [devices, setDevices] = useState(SEED.devices);
  const [links, setLinks] = useState(SEED.links);
  const [groups, setGroups] = useState(SEED.groups);

  const [tab, setTab] = useState("hld");
  const [selHld, setSelHld] = useState("B1");
  const [connectMode, setConnectMode] = useState(false);
  const [pendingA, setPendingA] = useState(null);
  const [selLld, setSelLld] = useState("B21");
  const [selDev, setSelDev] = useState(null);
  const [comboSel, setComboSel] = useState(["B1", "B2", "B21", "B211"]);
  const [tableFilter, setTableFilter] = useState("all");
  const [bomBlock, setBomBlock] = useState("B1");
  const [bomDesc, setBomDesc] = useState(true);
  const [showPorts, setShowPorts] = useState(true);

  const [fModel, setFModel] = useState(Object.keys(MODELS)[0]);
  const [fCount, setFCount] = useState(2);
  const [fScope, setFScope] = useState("internal");
  const [fTarget, setFTarget] = useState("");
  const [fPattern, setFPattern] = useState("mesh");
  const [fPer, setFPer] = useState(1);
  const [fSpeed, setFSpeed] = useState(100);
  const [fBO, setFBO] = useState(true);

  const devById = useMemo(() => Object.fromEntries(devices.map((d) => [d.id, d])), [devices]);
  const blockById = useMemo(() => Object.fromEntries(blocks.map((b) => [b.id, b])), [blocks]);
  const devsOf = (bid) => devices.filter((d) => d.blockId === bid);

  const treeRows = useMemo(() => {
    const walk = (pid, depth) =>
      blocks.filter((b) => (b.parentId || null) === pid).flatMap((b) => [{ b, depth }, ...walk(b.id, depth + 1)]);
    return walk(null, 0);
  }, [blocks]);

  function descendants(id) {
    const out = [];
    const walk = (pid) => blocks.filter((b) => b.parentId === pid).forEach((b) => { out.push(b.id); walk(b.id); });
    walk(id);
    return out;
  }
  const subtreeDevCount = (id) => devsOf(id).length + descendants(id).reduce((s, k) => s + devsOf(k).length, 0);
  const rootOf = (id) => { let b = blockById[id]; while (b && b.parentId) b = blockById[b.parentId]; return b?.id; };

  /* ---------- 操作 ---------- */
  function addBlock(type) {
    const n = blocks.filter((b) => b.type === type).length + 1;
    setBlocks([...blocks, {
      id: uid("B"), name: `${TYPES[type].label.toUpperCase().replace(/\s+/g, "-")}-${n}`,
      type, parentId: null, x: 80 + Math.random() * 500, y: 80 + Math.random() * 320,
    }]);
  }
  function addChild(parentId, name) {
    if (!name.trim()) return;
    setBlocks([...blocks, { id: uid("B"), name: name.trim().toUpperCase(), type: "sub", parentId, x: 0, y: 0 }]);
  }
  function renameBlock(id, name) { setBlocks(blocks.map((b) => (b.id === id ? { ...b, name } : b))); }
  function deleteBlock(id) {
    const dead = new Set([id, ...descendants(id)]);
    const deadDevs = new Set(devices.filter((d) => dead.has(d.blockId)).map((d) => d.id));
    const remain = links.filter((l) => !deadDevs.has(l.aDev) && !deadDevs.has(l.bDev));
    const live = new Set(remain.map((l) => l.groupId));
    setBlocks(blocks.filter((b) => !dead.has(b.id)));
    setBlockLinks(blockLinks.filter((l) => !dead.has(l.a) && !dead.has(l.b)));
    setDevices(devices.filter((d) => !deadDevs.has(d.id)));
    setLinks(remain);
    setGroups(groups.filter((g) => live.has(g.id) && !dead.has(g.blockId)));
    if (selHld === id) setSelHld(null);
    if (dead.has(selLld)) setSelLld(null);
  }
  function addDevices(blockId, model, count) {
    const blk = blockById[blockId];
    if (!blk) return;
    const base = blk.name.replace(/\s+/g, "-").toUpperCase();
    const start = devsOf(blockId).length;
    const add = [];
    for (let i = 1; i <= count; i++)
      add.push({ id: uid("D"), blockId, model, name: `${base}-${String(start + i).padStart(2, "0")}`, breakouts: {} });
    setDevices([...devices, ...add]);
  }
  function deleteDevice(id) {
    const remain = links.filter((l) => l.aDev !== id && l.bDev !== id);
    const live = new Set(remain.map((l) => l.groupId));
    setDevices(devices.filter((d) => d.id !== id));
    setLinks(remain);
    setGroups(groups.filter((g) => live.has(g.id)));
    if (selDev === id) setSelDev(null);
  }
  function deleteGroup(gid) {
    setLinks(links.filter((l) => l.groupId !== gid));
    setGroups(groups.filter((g) => g.id !== gid));
  }
  function createGroup() {
    const blk = blockById[selLld];
    if (!blk) return;
    const gid = uid("G");
    let res, label;
    if (fScope === "internal") {
      res = buildGroupLinks({
        kind: "internal", devsA: devsOf(selLld), pattern: fPattern, per: fPer, speed: fSpeed,
        groupId: gid, tag: `${blk.name} ${fPattern === "mesh" ? "full-mesh" : "ring"}`,
        existing: links, descA: true, descB: true, allowBO: fBO,
      });
      label = `${blk.name} 域内 · ${fPattern === "mesh" ? "full-mesh" : "手拖手(ring)"} · ${fPer}×${fSpeed}G`;
    } else {
      const tgt = blockById[fTarget];
      if (!tgt) { alert("请选择上联目标域"); return; }
      res = buildGroupLinks({
        kind: "cross", devsA: devsOf(selLld), devsB: devsOf(fTarget), per: fPer, speed: fSpeed,
        groupId: gid, tag: `${blk.name} → ${tgt.name}`,
        existing: links, descA: true, descB: false, allowBO: fBO,
      });
      label = `${blk.name} → ${tgt.name}${tgt.id === blk.parentId ? "(父域)" : ""} · 每对 ${fPer}×${fSpeed}G`;
    }
    if (res.error) { alert("生成失败:" + res.error); return; }
    setLinks([...links, ...res.added]);
    if (Object.keys(res.bo).length)
      setDevices(devices.map((d) => (res.bo[d.id] ? { ...d, breakouts: res.bo[d.id] } : d)));
    setGroups([...groups, { id: gid, blockId: selLld, label }]);
  }
  function manualBreakout(devId, port) {
    const dev = devById[devId];
    setDevices(devices.map((d) => (d.id === devId ? { ...d, breakouts: { ...(dev.breakouts || {}), [port.name]: port.bo[0] } } : d)));
  }
  function restoreBreakout(devId, portName) {
    const dev = devById[devId];
    const used = usedPortsOf(devId, links);
    if ([1, 2, 3, 4].some((k) => used.has(`${portName}/${k}`))) { alert("子端口仍被占用,先删除相关连线组"); return; }
    const nb = { ...(dev.breakouts || {}) };
    delete nb[portName];
    setDevices(devices.map((d) => (d.id === devId ? { ...d, breakouts: nb } : d)));
  }

  /* ---------- HLD 画布拖拽 ---------- */
  const svgRef = useRef(null);
  const dragRef = useRef(null);
  const toPt = (e) => {
    const r = svgRef.current.getBoundingClientRect();
    return { x: ((e.clientX - r.left) * 1000) / r.width, y: ((e.clientY - r.top) * 560) / r.height };
  };
  function blockDown(e, b) {
    e.stopPropagation();
    setSelHld(b.id);
    if (connectMode) {
      if (!pendingA) setPendingA(b.id);
      else if (pendingA === b.id) setPendingA(null);
      else {
        const exists = blockLinks.some((l) => (l.a === pendingA && l.b === b.id) || (l.a === b.id && l.b === pendingA));
        if (!exists) setBlockLinks([...blockLinks, { id: uid("BL"), a: pendingA, b: b.id }]);
        setPendingA(null);
      }
      return;
    }
    const p = toPt(e);
    dragRef.current = { id: b.id, dx: p.x - b.x, dy: p.y - b.y };
  }
  function svgMove(e) {
    if (!dragRef.current) return;
    const p = toPt(e);
    const { id, dx, dy } = dragRef.current;
    setBlocks((bs) => bs.map((b) => (b.id === id
      ? { ...b, x: Math.max(4, Math.min(836, p.x - dx)), y: Math.max(4, Math.min(488, p.y - dy)) } : b)));
  }
  const svgUp = () => { dragRef.current = null; };

  /* ---------- 派生:光模块统计(含 breakout 归并) ---------- */
  function countOptics(devIdSet) {
    const counts = {};
    const boUsed = {};
    links.forEach((l) => {
      [["aDev", "aPort", "aType"], ["bDev", "bPort", "bType"]].forEach(([dk, pk, tk]) => {
        const dev = devById[l[dk]];
        if (!dev || (devIdSet && !devIdSet.has(dev.id))) return;
        const par = parentBO(dev, l[pk]);
        if (par) (boUsed[dev.id] = boUsed[dev.id] || new Set()).add(par);
        else counts[`${l[tk]} ${l.speed}G`] = (counts[`${l[tk]} ${l.speed}G`] || 0) + 1;
      });
    });
    Object.entries(boUsed).forEach(([devId, set]) => {
      const dev = devById[devId];
      const nat = expandNative(dev.model);
      set.forEach((p) => {
        const n = nat.find((x) => x.name === p);
        const cs = dev.breakouts[p];
        const k = `${n.type} ${n.speed}G → 4×${cs}G 分支`;
        counts[k] = (counts[k] || 0) + 1;
      });
    });
    return counts;
  }

  function exportXlsx() {
    try {
      const rows = links.map((l, i) => {
        const a = devById[l.aDev], b = devById[l.bDev];
        const mod = (dev, port, type) => (parentBO(dev, port) ? `${type} 4×${l.speed}G分支口` : `${type} ${l.speed}G`);
        return {
          "线缆编号": `CAB-${String(i + 1).padStart(4, "0")}`,
          "A端设备": a?.name, "A端接口": l.aPort, "A端模块": mod(a, l.aPort, l.aType),
          "B端设备": b?.name, "B端接口": l.bPort, "B端模块": mod(b, l.bPort, l.bType),
          "带宽": `${l.speed}G`, "用途": l.tag,
          "A端域": blockById[a?.blockId]?.name, "B端域": blockById[b?.blockId]?.name,
        };
      });
      const dev = {};
      devices.forEach((d) => (dev[d.model] = (dev[d.model] || 0) + 1));
      const opt = countOptics(null);
      const bomRows = [
        ...Object.entries(dev).map(([m, n]) => ({ 类别: "设备", 型号: m, 数量: n })),
        ...Object.entries(opt).map(([m, n]) => ({ 类别: "光模块/分支", 型号: m, 数量: n })),
      ];
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows), "Patching");
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(bomRows), "BOM");
      XLSX.writeFile(wb, "dc-design-patching-bom.xlsx");
    } catch (e) { alert("导出失败(沙箱可能限制下载):" + e.message); }
  }

  /* ---------- HLD ---------- */
  function renderHLD() {
    const tops = blocks.filter((b) => !b.parentId);
    const sel = blockById[selHld];
    return (
      <div className="fp-body">
        <div className="fp-panel" style={{ width: 180, flexShrink: 0 }}>
          <h3>Block 模板库</h3>
          {TOP_TYPES.map((t) => (
            <div key={t} className="fp-list-item" onClick={() => addBlock(t)}>
              <span><span style={{ display: "inline-block", width: 9, height: 9, borderRadius: 2, background: TYPES[t].color, marginRight: 7 }} />{TYPES[t].label}</span>
              <span style={{ color: "#A0AEBD" }}>＋</span>
            </div>
          ))}
          <div className="fp-hint">点击添加到画布;子域在检查器或 LLD 页签里逐层添加,层级不限深度。</div>
          <button className={"fp-btn " + (connectMode ? "pri" : "")} style={{ width: "100%", marginTop: 12 }}
            onClick={() => { setConnectMode(!connectMode); setPendingA(null); }}>
            {connectMode ? "连线模式:开(再点关闭)" : "块间连线模式"}
          </button>
        </div>

        <div className="fp-panel" style={{ flex: 1, padding: 8 }}>
          <svg ref={svgRef} viewBox="0 0 1000 560" style={{ width: "100%", display: "block", borderRadius: 8, background: "#0F2440", touchAction: "none" }}
            onPointerMove={svgMove} onPointerUp={svgUp} onPointerLeave={svgUp}
            onPointerDown={() => { setSelHld(null); setPendingA(null); }}>
            <defs>
              <pattern id="grid" width="28" height="28" patternUnits="userSpaceOnUse">
                <path d="M28 0H0V28" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="1" />
              </pattern>
            </defs>
            <rect width="1000" height="560" fill="url(#grid)" />
            {blockLinks.map((l) => {
              const a = blockById[l.a], b = blockById[l.b];
              if (!a || !b) return null;
              return (
                <line key={l.id} x1={a.x + 80} y1={a.y + 34} x2={b.x + 80} y2={b.y + 34}
                  stroke="#5C7AA3" strokeWidth="2" strokeDasharray="6 4" style={{ cursor: "pointer" }}
                  onPointerDown={(e) => { e.stopPropagation(); setBlockLinks(blockLinks.filter((x) => x.id !== l.id)); }}>
                  <title>块间规划连接 · 点击删除</title>
                </line>
              );
            })}
            {tops.map((b) => {
              const kids = blocks.filter((k) => k.parentId === b.id);
              const nDev = subtreeDevCount(b.id);
              const active = selHld === b.id, pend = pendingA === b.id;
              return (
                <g key={b.id} transform={`translate(${b.x},${b.y})`} style={{ cursor: connectMode ? "crosshair" : "grab" }}
                  onPointerDown={(e) => blockDown(e, b)}>
                  <rect width="160" height="68" rx="9" fill="#13294B"
                    stroke={pend ? "#FFD166" : active ? "#F2762E" : TYPES[b.type].color}
                    strokeWidth={active || pend ? 2.5 : 1.3} strokeDasharray={pend ? "5 4" : "none"} />
                  <rect width="160" height="4" rx="2" fill={TYPES[b.type].color} />
                  <text x="10" y="25" fill="#fff" fontSize="13" fontWeight="700" className="fp-mono">{b.name}</text>
                  <text x="10" y="42" fill="#9FB3C8" fontSize="10">{TYPES[b.type].label} · 设备 {nDev} 台(含子域)</text>
                  {kids.length > 0 && (
                    <text x="10" y="58" fill="#7B93AD" fontSize="9">└ {kids.map((k) => k.name).join(" · ")}</text>
                  )}
                </g>
              );
            })}
          </svg>
          <div className="fp-hint">拖动 block 排版 · 连线模式下依次点击两个 block 建立块间规划关系(虚线,点击可删)</div>
        </div>

        <div className="fp-panel" style={{ width: 250, flexShrink: 0 }}>
          <h3>检查器</h3>
          {!sel && <div className="fp-hint">点击画布上的 block 查看详情。</div>}
          {sel && (
            <div>
              <span className="fp-label">名称</span>
              <input className="fp-input fp-mono" style={{ width: "100%", marginBottom: 10 }}
                value={sel.name} onChange={(e) => renameBlock(sel.id, e.target.value.toUpperCase())} />
              <ChildEditor parent={sel} kids={blocks.filter((k) => k.parentId === sel.id)}
                onAdd={addChild} onDel={deleteBlock} onOpen={(id) => { setSelLld(id); setTab("lld"); }} />
              <div className="fp-row" style={{ marginTop: 12 }}>
                <button className="fp-btn pri" onClick={() => { setSelLld(sel.id); setTab("lld"); }}>进入 LLD →</button>
                <button className="fp-btn danger" onClick={() => deleteBlock(sel.id)}>删除</button>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  /* ---------- 域树列表 ---------- */
  function treeList(onPick, cur) {
    return treeRows.map(({ b, depth }) => (
      <div key={b.id} className={"fp-list-item " + (cur === b.id ? "on" : "")}
        style={{ paddingLeft: 9 + depth * 16 }} onClick={() => onPick(b.id)}>
        <span className="fp-mono" style={{ fontSize: 12 }}>{depth > 0 ? "└ " : ""}{b.name}</span>
        <span style={{ color: "#A0AEBD", fontSize: 11 }}>{devsOf(b.id).length}台</span>
      </div>
    ));
  }

  /* ---------- LLD ---------- */
  function renderLLD() {
    const blk = blockById[selLld];
    const myDevs = blk ? devsOf(selLld) : [];
    const myGroups = groups.filter((g) => g.blockId === selLld);
    const excluded = blk ? new Set([selLld, ...descendants(selLld)]) : new Set();
    const hldNb = new Set(blockLinks.flatMap((l) => {
      const r = rootOf(selLld);
      if (l.a === r) return [l.b];
      if (l.b === r) return [l.a];
      return [];
    }));
    const rank = (b) => (b.id === blk?.parentId ? 0 : hldNb.has(b.id) || hldNb.has(rootOf(b.id)) ? 1 : 2);
    const candidates = blocks
      .filter((b) => !excluded.has(b.id) && devsOf(b.id).length > 0)
      .sort((a, b) => rank(a) - rank(b));
    const dev = devById[selDev];

    return (
      <div className="fp-body">
        <div className="fp-panel" style={{ width: 195, flexShrink: 0 }}>
          <h3>域树(任意深度)</h3>
          {treeList(setSelLld, selLld)}
        </div>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 14, minWidth: 0 }}>
          {!blk && <div className="fp-panel">请选择一个域。</div>}
          {blk && (
            <>
              <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
                <div className="fp-panel" style={{ flex: "1 1 300px" }}>
                  <h3>设备 · {blk.name}(点行看端口明细)</h3>
                  <div className="fp-row">
                    <select className="fp-sel" value={fModel} onChange={(e) => setFModel(e.target.value)} style={{ maxWidth: 210 }}>
                      {Object.keys(MODELS).map((m) => (<option key={m} value={m}>{MODELS[m].vendor} {m}</option>))}
                    </select>
                    <input className="fp-input" type="number" min="1" max="16" value={fCount} style={{ width: 56 }}
                      onChange={(e) => setFCount(Math.max(1, Math.min(16, +e.target.value || 1)))} />
                    <button className="fp-btn pri" onClick={() => addDevices(selLld, fModel, fCount)}>添加</button>
                  </div>
                  <div style={{ marginTop: 10, maxHeight: 170, overflow: "auto" }}>
                    {myDevs.map((d) => {
                      const eff = effectivePorts(d);
                      const used = usedPortsOf(d.id, links).size;
                      const pct = eff.length ? Math.round((used / eff.length) * 100) : 0;
                      return (
                        <div key={d.id} className="fp-group" style={{ marginBottom: 6, cursor: "pointer", borderColor: selDev === d.id ? "#F2762E" : undefined }}
                          onClick={() => setSelDev(d.id)}>
                          <span style={{ minWidth: 0 }}>
                            <span className="fp-mono" style={{ fontSize: 12 }}>{d.name}</span>
                            <span style={{ color: "#8A99A8", marginLeft: 8, fontSize: 11 }}>{d.model} · {used}/{eff.length} 口</span>
                            <span className="fp-bar" style={{ width: 110, marginTop: 4 }}><i style={{ width: pct + "%" }} /></span>
                          </span>
                          <button className="fp-btn danger sm" onClick={(e) => { e.stopPropagation(); deleteDevice(d.id); }}>删</button>
                        </div>
                      );
                    })}
                    {!myDevs.length && <div className="fp-hint">还没有设备。主域也可以有自己的设备(如 External 的边界路由器)。</div>}
                  </div>
                </div>

                <div className="fp-panel" style={{ flex: "1 1 330px" }}>
                  <h3>连线规则(生成式)</h3>
                  <div className="fp-row" style={{ marginBottom: 8 }}>
                    <select className="fp-sel" value={fScope} onChange={(e) => setFScope(e.target.value)}>
                      <option value="internal">域内互联</option>
                      <option value="cross">上联 / 跨域</option>
                    </select>
                    {fScope === "internal" ? (
                      <select className="fp-sel" value={fPattern} onChange={(e) => setFPattern(e.target.value)}>
                        <option value="mesh">全交叉 full-mesh</option>
                        <option value="ring">手拖手 ring</option>
                      </select>
                    ) : (
                      <select className="fp-sel" value={fTarget} onChange={(e) => setFTarget(e.target.value)} style={{ maxWidth: 220 }}>
                        <option value="">选择目标域…</option>
                        {candidates.map((c) => (
                          <option key={c.id} value={c.id}>
                            {c.name}{c.id === blk.parentId ? "(父域)" : hldNb.has(c.id) || hldNb.has(rootOf(c.id)) ? "(HLD 已规划)" : ""}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                  <div className="fp-row" style={{ marginBottom: 8 }}>
                    <span className="fp-label" style={{ margin: 0 }}>每对线数</span>
                    <input className="fp-input" type="number" min="1" max="8" value={fPer} style={{ width: 52 }}
                      onChange={(e) => setFPer(Math.max(1, Math.min(8, +e.target.value || 1)))} />
                    <span className="fp-label" style={{ margin: 0 }}>速率</span>
                    <select className="fp-sel" value={fSpeed} onChange={(e) => setFSpeed(+e.target.value)}>
                      {SPEEDS.map((s) => (<option key={s} value={s}>{s}G</option>))}
                    </select>
                    <label style={{ fontSize: 11.5, color: "#5A6B7E" }}>
                      <input type="checkbox" checked={fBO} onChange={(e) => setFBO(e.target.checked)} /> 端口不足时自动 breakout
                    </label>
                  </div>
                  <button className="fp-btn pri" style={{ marginBottom: 10 }} onClick={createGroup}>生成连线 + 自动分配端口</button>
                  <div style={{ maxHeight: 130, overflow: "auto" }}>
                    {myGroups.map((g) => (
                      <div key={g.id} className="fp-group">
                        <span style={{ fontSize: 12 }}>{g.label}
                          <span style={{ color: "#8A99A8", marginLeft: 6 }}>({links.filter((l) => l.groupId === g.id).length} 根)</span>
                        </span>
                        <button className="fp-btn danger sm" onClick={() => deleteGroup(g.id)}>删组</button>
                      </div>
                    ))}
                    {!myGroups.length && <div className="fp-hint">上联目标可以选父域(比如 Internet → External 的路由器),也可以跨域。速率不被型号支持时会直接报错。</div>}
                  </div>
                </div>

                <div className="fp-panel" style={{ flex: "0 1 240px" }}>
                  <h3>子域 · {blk.name}</h3>
                  <ChildEditor parent={blk} kids={blocks.filter((k) => k.parentId === blk.id)}
                    onAdd={addChild} onDel={deleteBlock} onOpen={setSelLld} />
                  <div className="fp-hint">例:Internet 下再建 DISTRIBUTION / ACCESS 两层,各自加设备、逐层定义上联。</div>
                </div>
              </div>

              <div className="fp-panel">
                <div className="fp-row" style={{ justifyContent: "space-between" }}>
                  <h3 style={{ margin: 0 }}>LLD 拓扑 · {blk.name}</h3>
                  <label style={{ fontSize: 12, color: "#5A6B7E" }}>
                    <input type="checkbox" checked={showPorts} onChange={(e) => setShowPorts(e.target.checked)} /> 显示端口号
                  </label>
                </div>
                <LldDiagram blockId={selLld} />
                <Legend />
              </div>
            </>
          )}
        </div>
        {dev && <DeviceDetail dev={dev} onClose={() => setSelDev(null)} />}
      </div>
    );
  }

  /* ---------- 设备端口明细抽屉 ---------- */
  function DeviceDetail({ dev, onClose }) {
    const conn = {};
    links.forEach((l) => {
      if (l.aDev === dev.id) conn[l.aPort] = { peer: devById[l.bDev]?.name, pp: l.bPort, sp: l.speed, tag: l.tag };
      if (l.bDev === dev.id) conn[l.bPort] = { peer: devById[l.aDev]?.name, pp: l.aPort, sp: l.speed, tag: l.tag };
    });
    const bo = dev.breakouts || {};
    const nat = expandNative(dev.model);
    const grp = {};
    effectivePorts(dev).forEach((p) => {
      const k = p.parent ? `${p.speed}G(breakout 子口)` : `${p.speed}G ${p.type}`;
      const g = (grp[k] = grp[k] || { t: 0, u: 0 });
      g.t++;
      if (conn[p.name]) g.u++;
    });
    return (
      <div className="fp-panel" style={{ width: 330, flexShrink: 0, maxHeight: 640, overflow: "auto" }}>
        <div className="fp-row" style={{ justifyContent: "space-between" }}>
          <h3 style={{ margin: 0 }} className="fp-mono">{dev.name}</h3>
          <button className="fp-btn sm" onClick={onClose}>关闭</button>
        </div>
        <div style={{ fontSize: 11.5, color: "#5A6B7E", marginBottom: 8 }}>{MODELS[dev.model]?.vendor} {dev.model} · 域 {blockById[dev.blockId]?.name}</div>
        <table className="fp-table" style={{ marginBottom: 10 }}>
          <thead><tr><th>端口组</th><th>总数</th><th>已用</th><th>剩余</th></tr></thead>
          <tbody>
            {Object.entries(grp).map(([k, g]) => (
              <tr key={k}><td>{k}</td><td>{g.t}</td><td>{g.u}</td><td style={{ fontWeight: 700, color: g.t - g.u === 0 ? "#B3392B" : "#1C7C4D" }}>{g.t - g.u}</td></tr>
            ))}
          </tbody>
        </table>
        <table className="fp-table">
          <thead><tr><th>端口</th><th>速率</th><th>状态</th><th></th></tr></thead>
          <tbody>
            {nat.flatMap((p) => {
              const cs = bo[p.name];
              if (cs) {
                return [
                  <tr key={p.name} style={{ background: "#FFF6EE" }}>
                    <td className="fp-mono">{p.name}</td><td>{p.speed}G</td>
                    <td>已拆分 4×{cs}G</td>
                    <td><button className="fp-btn sm" onClick={() => restoreBreakout(dev.id, p.name)}>恢复</button></td>
                  </tr>,
                  ...[1, 2, 3, 4].map((k) => {
                    const n = `${p.name}/${k}`;
                    const c = conn[n];
                    return (
                      <tr key={n}>
                        <td className="fp-mono" style={{ paddingLeft: 22 }}>{n}</td><td>{cs}G</td>
                        <td>{c ? <span className="fp-mono" style={{ fontSize: 11 }}>→ {c.peer} {c.pp}</span> : <span style={{ color: "#9AA8B6" }}>空闲</span>}</td>
                        <td></td>
                      </tr>
                    );
                  }),
                ];
              }
              const c = conn[p.name];
              return [
                <tr key={p.name}>
                  <td className="fp-mono">{p.name}</td><td>{p.speed}G</td>
                  <td>{c ? <span className="fp-mono" style={{ fontSize: 11 }}>→ {c.peer} {c.pp}</span> : <span style={{ color: "#9AA8B6" }}>空闲</span>}</td>
                  <td>{!c && p.bo ? <button className="fp-btn sm" onClick={() => manualBreakout(dev.id, p)}>拆4×{p.bo[0]}G</button> : null}</td>
                </tr>,
              ];
            })}
          </tbody>
        </table>
      </div>
    );
  }

  /* ---------- LLD 图 ---------- */
  function LldDiagram({ blockId }) {
    const myDevs = devsOf(blockId);
    const mine = new Set(myDevs.map((d) => d.id));
    const rel = links.filter((l) => mine.has(l.aDev) || mine.has(l.bDev));
    const extIds = [...new Set(rel.flatMap((l) => [l.aDev, l.bDev]).filter((i) => !mine.has(i)))];
    const extDevs = extIds.map((i) => devById[i]).filter(Boolean);
    if (!myDevs.length) return <div className="fp-hint">先添加设备并生成连线组,这里会自动渲染拓扑。</div>;

    const pos = {}, myIdx = {};
    spread(extDevs.length).forEach((x, i) => (pos[extDevs[i].id] = { x, y: 46 }));
    spread(myDevs.length).forEach((x, i) => { pos[myDevs[i].id] = { x, y: extDevs.length ? 300 : 170 }; myIdx[myDevs[i].id] = i; });

    const byPair = {};
    rel.forEach((l) => { const k = pairKey(l.aDev, l.bDev); (byPair[k] = byPair[k] || []).push(l); });
    const H = (extDevs.length ? 300 : 170) + 56 + 130;

    return (
      <svg viewBox={`0 0 1000 ${H}`} style={{ width: "100%", display: "block" }}>
        {Object.values(byPair).flatMap((arr) =>
          arr.map((l, idx) => {
            const A = pos[l.aDev], B = pos[l.bDev];
            if (!A || !B) return null;
            const col = SPEED_COLOR[l.speed] || "#888";
            const title = `${devById[l.aDev]?.name} ${l.aPort}  ⇄  ${devById[l.bDev]?.name} ${l.bPort} · ${l.speed}G · ${l.tag}`;
            const internal = mine.has(l.aDev) && mine.has(l.bDev);
            if (internal) {
              const i1 = myIdx[l.aDev], i2 = myIdx[l.bDev];
              const y0 = A.y + 52;
              const depth = 22 + Math.abs(i2 - i1) * 24 + idx * 11;
              return (
                <g key={l.id}>
                  <path d={`M ${A.x} ${y0} Q ${(A.x + B.x) / 2} ${y0 + depth * 2} ${B.x} ${y0}`}
                    fill="none" stroke={col} strokeWidth="1.7" opacity="0.85"><title>{title}</title></path>
                  {showPorts && (<>
                    <text x={A.x + (idx % 2 ? 16 : -16)} y={y0 + 12 + (idx % 3) * 10} fontSize="9" fill={col} textAnchor="middle" className="fp-mono">{l.aPort}</text>
                    <text x={B.x + (idx % 2 ? -16 : 16)} y={y0 + 12 + (idx % 3) * 10} fontSize="9" fill={col} textAnchor="middle" className="fp-mono">{l.bPort}</text>
                  </>)}
                </g>
              );
            }
            const top = A.y < B.y ? A : B, bot = A.y < B.y ? B : A;
            const topPort = A.y < B.y ? l.aPort : l.bPort;
            const botPort = A.y < B.y ? l.bPort : l.aPort;
            const off = (idx - (arr.length - 1) / 2) * 9;
            const x1 = top.x + off, y1 = top.y + 52, x2 = bot.x + off, y2 = bot.y;
            return (
              <g key={l.id}>
                <line x1={x1} y1={y1} x2={x2} y2={y2} stroke={col} strokeWidth="1.7" opacity="0.85"><title>{title}</title></line>
                {showPorts && (<>
                  <text x={x1 + (x2 - x1) * 0.16 + 4} y={y1 + (y2 - y1) * 0.16} fontSize="9" fill={col} className="fp-mono">{topPort}</text>
                  <text x={x1 + (x2 - x1) * 0.84 + 4} y={y1 + (y2 - y1) * 0.84} fontSize="9" fill={col} className="fp-mono">{botPort}</text>
                </>)}
              </g>
            );
          })
        )}
        {[...extDevs, ...myDevs].map((d) => {
          const p = pos[d.id];
          const isMine = mine.has(d.id);
          return (
            <g key={d.id} transform={`translate(${p.x - 75},${p.y})`} style={{ cursor: "pointer" }} onClick={() => setSelDev(d.id)}>
              <rect width="150" height="52" rx="7" fill={isMine ? "#10243F" : "#5C7AA3"}
                stroke={isMine ? TYPES[blockById[d.blockId]?.type]?.color || "#888" : "#44607F"} strokeWidth="1.4" />
              <text x="75" y="22" textAnchor="middle" fill="#fff" fontSize="11.5" fontWeight="700" className="fp-mono">{d.name}</text>
              <text x="75" y="40" textAnchor="middle" fill="#B8C8D8" fontSize="9">{d.model}{!isMine ? ` · ${blockById[d.blockId]?.name}` : ""}</text>
            </g>
          );
        })}
      </svg>
    );
  }

  function Legend() {
    return (
      <div className="fp-row" style={{ marginTop: 8 }}>
        {SPEEDS.map((s) => (
          <span key={s} style={{ fontSize: 11, color: "#5A6B7E" }}>
            <span style={{ display: "inline-block", width: 18, height: 3, background: SPEED_COLOR[s], verticalAlign: "middle", marginRight: 5, borderRadius: 2 }} />{s}G
          </span>
        ))}
        <span style={{ fontSize: 11, color: "#8A99A8" }}>(悬停连线看两端接口 · 点击设备看端口明细)</span>
      </div>
    );
  }

  /* ---------- 组合视图 ---------- */
  function renderCombo() {
    const all = treeRows.filter(({ b }) => devsOf(b.id).length > 0);
    const sel = comboSel.filter((id) => blockById[id] && devsOf(id).length > 0);
    const pos = {}, rowOf = {};
    sel.forEach((bid, r) => {
      const ds = devsOf(bid);
      spread(ds.length).forEach((x, i) => (pos[ds[i].id] = { x, y: 70 + r * 170 }));
      ds.forEach((d, i) => (rowOf[d.id] = { r, i }));
    });
    const inSel = new Set(sel.flatMap((bid) => devsOf(bid).map((d) => d.id)));
    const shown = links.filter((l) => inSel.has(l.aDev) && inSel.has(l.bDev));
    const byPair = {};
    shown.forEach((l) => { const k = pairKey(l.aDev, l.bDev); (byPair[k] = byPair[k] || []).push(l); });
    const H = 70 + sel.length * 170 + 40;

    return (
      <div className="fp-body">
        <div className="fp-panel" style={{ width: 210, flexShrink: 0 }}>
          <h3>框选要渲染的域</h3>
          {all.map(({ b, depth }) => (
            <label key={b.id} className="fp-list-item" style={{ cursor: "pointer", paddingLeft: 9 + depth * 14 }}>
              <span className="fp-mono" style={{ fontSize: 12 }}>{depth > 0 ? "└ " : ""}{b.name}</span>
              <input type="checkbox" checked={comboSel.includes(b.id)}
                onChange={(e) => setComboSel(e.target.checked ? [...comboSel, b.id] : comboSel.filter((x) => x !== b.id))} />
            </label>
          ))}
          <div className="fp-hint">只渲染两端都在所选域内的连线 —— 任意组合,层级随意。</div>
        </div>
        <div className="fp-panel" style={{ flex: 1 }}>
          <h3>组合拓扑({sel.length} 个域 · {shown.length} 根线)</h3>
          {!sel.length && <div className="fp-hint">勾选左侧域。</div>}
          {sel.length > 0 && (
            <svg viewBox={`0 0 1000 ${H}`} style={{ width: "100%", display: "block" }}>
              {sel.map((bid, r) => (
                <g key={bid}>
                  <rect x="14" y={42 + r * 170} width="972" height="118" rx="10" fill="#F4F7FA" stroke="#DCE3EB" />
                  <text x="26" y={60 + r * 170} fontSize="11" fontWeight="700" fill={TYPES[blockById[bid].type].color} className="fp-mono">{blockById[bid].name}</text>
                </g>
              ))}
              {Object.values(byPair).flatMap((arr) =>
                arr.map((l, idx) => {
                  const A = pos[l.aDev], B = pos[l.bDev];
                  const col = SPEED_COLOR[l.speed] || "#888";
                  const title = `${devById[l.aDev]?.name} ${l.aPort} ⇄ ${devById[l.bDev]?.name} ${l.bPort} · ${l.speed}G`;
                  if (rowOf[l.aDev].r === rowOf[l.bDev].r) {
                    const y0 = A.y + 50;
                    const depth = 14 + Math.abs(rowOf[l.aDev].i - rowOf[l.bDev].i) * 12 + idx * 8;
                    return (
                      <path key={l.id} d={`M ${A.x} ${y0} Q ${(A.x + B.x) / 2} ${y0 + depth * 1.6} ${B.x} ${y0}`}
                        fill="none" stroke={col} strokeWidth="1.5" opacity="0.85"><title>{title}</title></path>
                    );
                  }
                  const top = A.y < B.y ? A : B, bot = A.y < B.y ? B : A;
                  const off = (idx - (arr.length - 1) / 2) * 8;
                  return (
                    <path key={l.id}
                      d={`M ${top.x + off} ${top.y + 50} C ${top.x + off} ${top.y + 110}, ${bot.x + off} ${bot.y - 60}, ${bot.x + off} ${bot.y}`}
                      fill="none" stroke={col} strokeWidth="1.5" opacity="0.8"><title>{title}</title></path>
                  );
                })
              )}
              {sel.flatMap((bid) => devsOf(bid)).map((d) => {
                const p = pos[d.id];
                return (
                  <g key={d.id} transform={`translate(${p.x - 68},${p.y})`} style={{ cursor: "pointer" }} onClick={() => { setSelLld(d.blockId); setSelDev(d.id); setTab("lld"); }}>
                    <rect width="136" height="50" rx="7" fill="#10243F" stroke={TYPES[blockById[d.blockId].type].color} strokeWidth="1.3" />
                    <text x="68" y="21" textAnchor="middle" fill="#fff" fontSize="10.5" fontWeight="700" className="fp-mono">{d.name}</text>
                    <text x="68" y="38" textAnchor="middle" fill="#B8C8D8" fontSize="8.5">{d.model}</text>
                  </g>
                );
              })}
            </svg>
          )}
          <Legend />
        </div>
      </div>
    );
  }

  /* ---------- 按域 BOM ---------- */
  function renderBom() {
    const scopeIds = bomBlock === "all" ? null : new Set([bomBlock, ...(bomDesc ? descendants(bomBlock) : [])]);
    const scopeDevs = devices.filter((d) => !scopeIds || scopeIds.has(d.blockId));
    const scopeDevIds = new Set(scopeDevs.map((d) => d.id));
    const devBom = {};
    scopeDevs.forEach((d) => (devBom[d.model] = (devBom[d.model] || 0) + 1));
    const optics = countOptics(scopeIds ? scopeDevIds : null);
    const title = bomBlock === "all" ? "全部" : blockById[bomBlock]?.name + (bomDesc ? "(含子域)" : "");

    return (
      <div className="fp-body">
        <div className="fp-panel" style={{ width: 210, flexShrink: 0 }}>
          <h3>选择域出采购清单</h3>
          <div className={"fp-list-item " + (bomBlock === "all" ? "on" : "")} onClick={() => setBomBlock("all")}>
            <span style={{ fontSize: 12 }}>全部</span>
          </div>
          {treeList(setBomBlock, bomBlock)}
          <label style={{ fontSize: 12, color: "#5A6B7E", display: "block", marginTop: 8 }}>
            <input type="checkbox" checked={bomDesc} onChange={(e) => setBomDesc(e.target.checked)} /> 包含子域
          </label>
          <div className="fp-hint">例:选 DC-CORE 就是"Build DC Core 要买什么";光模块按连线端点归属到设备所在域。</div>
        </div>
        <div style={{ flex: 1, display: "flex", gap: 14, flexWrap: "wrap" }}>
          <div className="fp-panel" style={{ flex: "1 1 280px" }}>
            <h3>设备 · {title}</h3>
            <table className="fp-table">
              <thead><tr><th>型号</th><th>数量</th></tr></thead>
              <tbody>
                {Object.entries(devBom).map(([m, n]) => (<tr key={m}><td className="fp-mono">{m}</td><td>{n}</td></tr>))}
                {!Object.keys(devBom).length && <tr><td colSpan="2" style={{ color: "#9AA8B6" }}>该域没有设备</td></tr>}
              </tbody>
            </table>
          </div>
          <div className="fp-panel" style={{ flex: "1 1 320px" }}>
            <h3>光模块 / 分支线 · {title}</h3>
            <table className="fp-table">
              <thead><tr><th>类型</th><th>数量</th></tr></thead>
              <tbody>
                {Object.entries(optics).map(([m, n]) => (<tr key={m}><td className="fp-mono">{m}</td><td>{n}</td></tr>))}
                {!Object.keys(optics).length && <tr><td colSpan="2" style={{ color: "#9AA8B6" }}>该域没有连线端点</td></tr>}
              </tbody>
            </table>
            <div className="fp-hint">已拆分端口按"1 个分支模块/线"归并统计,不重复计 4 个子口。正式版可加 DAC/AOC 介质与距离选光模块型号(SR/LR)。</div>
          </div>
        </div>
      </div>
    );
  }

  /* ---------- Patching 表 ---------- */
  function renderTable() {
    const opts = treeRows.filter(({ b }) => devsOf(b.id).length > 0);
    const scope = tableFilter === "all" ? null : new Set([tableFilter, ...descendants(tableFilter)]);
    const shown = links.filter((l) => {
      if (!scope) return true;
      return scope.has(devById[l.aDev]?.blockId) || scope.has(devById[l.bDev]?.blockId);
    });
    return (
      <div className="fp-body" style={{ flexDirection: "column" }}>
        <div className="fp-panel" style={{ width: "100%" }}>
          <div className="fp-row" style={{ justifyContent: "space-between", marginBottom: 10 }}>
            <h3 style={{ margin: 0 }}>Patching 表({shown.length} 根)</h3>
            <div className="fp-row">
              <select className="fp-sel" value={tableFilter} onChange={(e) => setTableFilter(e.target.value)}>
                <option value="all">全部域</option>
                {opts.map(({ b, depth }) => (<option key={b.id} value={b.id}>{"　".repeat(depth)}{b.name}(含子域)</option>))}
              </select>
              <button className="fp-btn pri" onClick={exportXlsx}>导出 Excel(Patching + BOM)</button>
            </div>
          </div>
          <div style={{ overflow: "auto", maxHeight: 480 }}>
            <table className="fp-table">
              <thead>
                <tr><th>#</th><th>A端设备</th><th>A端接口</th><th>A端模块</th><th>B端设备</th><th>B端接口</th><th>B端模块</th><th>带宽</th><th>用途</th></tr>
              </thead>
              <tbody>
                {shown.map((l, i) => {
                  const a = devById[l.aDev], b = devById[l.bDev];
                  const mod = (dev, port, type) => (parentBO(dev, port) ? `${type} 4×${l.speed}G分支` : `${type} ${l.speed}G`);
                  return (
                    <tr key={l.id}>
                      <td className="fp-mono">CAB-{String(i + 1).padStart(4, "0")}</td>
                      <td className="fp-mono">{a?.name}</td><td className="fp-mono">{l.aPort}</td><td>{mod(a, l.aPort, l.aType)}</td>
                      <td className="fp-mono">{b?.name}</td><td className="fp-mono">{l.bPort}</td><td>{mod(b, l.bPort, l.bType)}</td>
                      <td><span className="fp-chip" style={{ background: SPEED_COLOR[l.speed] + "26", color: SPEED_COLOR[l.speed] }}>{l.speed}G</span></td>
                      <td>{l.tag}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fp-app">
      <style>{CSS}</style>
      <div className="fp-hdr">
        <div>
          <h1>FABRIC&nbsp;PLANNER&nbsp;v2</h1>
          <small>模型驱动 · 任意深度域树 · breakout 感知端口分配 · 按域 BOM</small>
        </div>
        <div className="fp-tabs">
          {[["hld", "① HLD 画布"], ["lld", "② 域 LLD"], ["combo", "③ 框选组合图"], ["bom", "④ 按域 BOM"], ["table", "⑤ Patching 表"]].map(([k, lbl]) => (
            <button key={k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{lbl}</button>
          ))}
        </div>
      </div>
      {tab === "hld" && renderHLD()}
      {tab === "lld" && renderLLD()}
      {tab === "combo" && renderCombo()}
      {tab === "bom" && renderBom()}
      {tab === "table" && renderTable()}
    </div>
  );
}

/* ---------- 子域编辑器(任意层级通用) ---------- */
function ChildEditor({ parent, kids, onAdd, onDel, onOpen }) {
  const [name, setName] = useState("");
  return (
    <div>
      <span className="fp-label">子域({kids.length})</span>
      {kids.map((k) => (
        <div key={k.id} className="fp-group" style={{ marginBottom: 6 }}>
          <span className="fp-mono" style={{ fontSize: 12, cursor: "pointer" }} onClick={() => onOpen(k.id)}>└ {k.name}</span>
          <button className="fp-btn danger sm" onClick={() => onDel(k.id)}>删</button>
        </div>
      ))}
      <div className="fp-row">
        <input className="fp-input" placeholder="如 DISTRIBUTION" value={name} style={{ flex: 1, minWidth: 90 }}
          onChange={(e) => setName(e.target.value)} />
        <button className="fp-btn" onClick={() => { onAdd(parent.id, name); setName(""); }}>＋</button>
      </div>
    </div>
  );
}
