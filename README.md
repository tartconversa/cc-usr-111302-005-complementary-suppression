# 共享统计表的互补抑制与联合发布审计

本项目保存虚构数据共享及产品运营的合成表格与 Python 审计工具。`src/suppression_reader.py` 只负责解析文件；新增的发布审计器在整数域上精确评估主抑制格在所有已公开线性关系下的可行值集合，并搜索满足保护要求的最小损失互补抑制方案。所有地区、机构、产品与人数均为合成。

## 字段与单位

cells 给非负整数格及公开上下界；`true_value` 仅用于本地保护目标验证，**不是对手知识**，从不作为约束进入可行域求解。queries 的系数向量映射同一格顺序，`published_prior` 不可再隐藏；candidates 带固定 `suppression_cost`，只能被额外隐藏，答案不可修改、不添加噪声。

`material-index.json` 记录全部输入内容哈希；fixtures 保存原始资料与配置，计算输出放 `.workspace-output`，原始资料不应被覆盖。

## 审计器做什么

1. **可行域泄露审计**：把全部已发布查询（含跨表）与容量界联立为整数线性系统，逐值枚举主格真实可取的整数值（真实支持），报告每个值的可行见证赋值，含最小/最大端点见证。区间长度 `max-min+1` 仅作对照字段；存在奇偶约束或内部洞时以真实支持计数为准，不冒充最小可行值个数 k。
2. **保护要求验证**：分别检查可行整数值个数 ≥ k、相对真实格值的下侧距离与上侧距离（端点口径，另报距真值最近的可行值作参考）。
3. **候选答案矛盾检测**：以整数可行性为准；对整数无解的系统再做 Fourier–Motzkin 实数松弛判定，标记"实数有解、整数无解"（如 `2x-y=0` 与 `x+y=10`）。矛盾候选若公开即暴露无解，必须隐藏。
4. **冗余查询检测**：移除查询后整数可行域与主格投影不变则标记冗余（如 `2x+2y=20` 相对 `x+y=10`），用于解释隐藏成本去向。
5. **互补抑制搜索**：分支定界枚举候选的隐藏/保留决策，最小化抑制成本之和。预算内穷尽给 `optimal`；预算耗尽时交付已验证可行的方案与**合法下界**并显式标注未证明最优；任何隐藏组合都不满足保护时给 `no_protection_scheme`。
6. **跨表联合发布**：`--extra-release` 传入的其他发布表查询与配置内 `adversary_extra_releases` 联合加入对手知识，均不可隐藏。单表安全不代表合起来安全。

## 边界声明（报告 disclaimer 同步输出）

本工具是基于已声明公开规则的精确整数审计，**不是差分隐私机制**；不提供差分隐私保证，也不抵抗未知外部信息（其他发布、背景知识、联动攻击）。真实表仅作为可行见证参与本地一致性检查，对手可见的只有公开容量界与已发布查询的系数和答案。

## 运行

Python 3.11 以上，纯标准库，无第三方依赖。

    python -m src.suppression_reader fixtures/cells.json
    python -m src.release_audit fixtures/cells.json fixtures/queries.json fixtures/suppression.json
    python -m src.release_audit fixtures/cells.json fixtures/queries.json \
        fixtures/suppression_cross_table.json \
        --extra-release fixtures/queries_neighbor_table.json \
        --output .workspace-output/cross-table-report.json

处理不可信输入目录时用隔离模式（脚本入口会自行定位仓库根，不依赖 PYTHONPATH）：

    python -I src/release_audit.py fixtures/cells.json fixtures/queries.json fixtures/suppression.json

    python -m compileall -q src tests
    python -m unittest discover -s tests -v

## 固定容器

    docker build -t complementary-suppression:local .
    docker run --rm complementary-suppression:local

容器镜像以完整 digest 固定，默认仅检查输入契约；实现新增分析功能所需依赖由开发者明确登记。当前审计器仍只依赖标准库，无需新增依赖。
