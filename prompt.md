这个项目按 docs/engineering-spec.md 实施,这是工程规格书,不是建议书 —— 第 0 节的六条硬性原则、第 9 节的施工顺序(S1→S8)和禁止事项清单必须严格遵守。行为基准是 prototype/network-designer.jsx,规则引擎的输出要和原型种子场景一致(第 10 节)。
现在开始 S1(骨架):按规格 §2 的目录结构创建文件、初始化 backend(FastAPI + SQLAlchemy + Alembic,SQLite 连接串)和 frontend(Vite + React + TS),写好 Makefile 和 docker-compose,做到 make dev 能起两端、GET /api/v1/health 返回 200。S1 完成后停下来等我确认验收,再进 S2。


重要:不要超出 S1 范围,不要预先创建 S2 之后才用到的文件;不要引入规格书未列出的依赖。
