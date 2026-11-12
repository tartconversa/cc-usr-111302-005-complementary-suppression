# 共享统计表的互补抑制与联合发布审计

本项目保存虚构数据共享及产品运营的合成表格与Python读取工具。当前工具只解析文件并显示记录数，不执行统计推断、优化、估计或校准。所有地区、机构、产品与人数均为合成。

## 字段与单位

cells给非负整数格及公开上下界；true_value仅用于本地保护目标验证，不是对手知识。queries的系数向量映射同一格顺序，published_prior不可再隐藏。

material-index.json记录全部输入内容哈希；fixtures保存原始资料与配置，计算输出可放.workspace-output，原始资料不应被覆盖。

## 运行已有读取器

Python 3.11以上，标准库即可，不需安装第三方依赖。

    python -m src.suppression_reader fixtures/cells.json
    python -m compileall -q src tests
    python -m unittest discover -s tests -v

## 固定容器

    docker build -t complementary-suppression:local .
    docker run --rm complementary-suppression:local

容器镜像以完整digest固定，默认仅检查输入契约；实现新增分析功能所需依赖由开发者明确登记。
