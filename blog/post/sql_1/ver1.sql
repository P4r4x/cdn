USE szy;

DECLARE @input_year INT = 2020;        -- 自定义年份
DECLARE @start_month INT = 1;          -- 起始月（含）
DECLARE @end_month INT = 12;            -- 终止月（含）

-- 生成月份序号辅助表 (1~12月)
WITH Months AS (
    SELECT 1 AS m UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4
    UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8
    UNION ALL SELECT 9 UNION ALL SELECT 10 UNION ALL SELECT 11 UNION ALL SELECT 12
),
-- 展开科目明细到月度颗粒度
UnpivotedData AS (
    SELECT 
        Y.kjnd,
        Y.kmdm,
        M.m AS month_num,
        Y.ncj,
        Y.ncd,
        CASE M.m 
            WHEN 1 THEN Y.yj1 WHEN 2 THEN Y.yj2 WHEN 3 THEN Y.yj3 WHEN 4 THEN Y.yj4
            WHEN 5 THEN Y.yj5 WHEN 6 THEN Y.yj6 WHEN 7 THEN Y.yj7 WHEN 8 THEN Y.yj8
            WHEN 9 THEN Y.yj9 WHEN 10 THEN Y.yj10 WHEN 11 THEN Y.yj11 WHEN 12 THEN Y.yj12
        END AS yj,
        CASE M.m 
            WHEN 1 THEN Y.yd1 WHEN 2 THEN Y.yd2 WHEN 3 THEN Y.yd3 WHEN 4 THEN Y.yd4
            WHEN 5 THEN Y.yd5 WHEN 6 THEN Y.yd6 WHEN 7 THEN Y.yd7 WHEN 8 THEN Y.yd8
            WHEN 9 THEN Y.yd9 WHEN 10 THEN Y.yd10 WHEN 11 THEN Y.yd11 WHEN 12 THEN Y.yd12
        END AS yd
    FROM GL_Yebk Y
    CROSS JOIN Months M
    WHERE 
        Y.kjnd = @input_year
        AND NOT EXISTS (
            SELECT 1 
            FROM GL_Yebk AS child 
            WHERE child.kmdm LIKE Y.kmdm + '%'
        )
),
-- 按科目聚合期初和本期金额
AggregatedData AS (
    SELECT 
        kjnd,
        kmdm,
        ROUND(SUM(ncj), 2) AS ncj_total,
        ROUND(SUM(ncd), 2) AS ncd_total,
        -- 期初 = 年初数 + 起始月之前的月度发生额
        ROUND(SUM(
            CASE 
                WHEN month_num < @start_month THEN yj 
                ELSE 0 
            END
        ), 2) AS yj_begin,
        ROUND(SUM(
            CASE 
                WHEN month_num < @start_month THEN yd 
                ELSE 0 
            END
        ), 2) AS yd_begin,
        -- 本期 = 起始月到终止月的月度发生额
        ROUND(SUM(
            CASE 
                WHEN month_num BETWEEN @start_month AND @end_month THEN yj 
                ELSE 0 
            END
        ), 2) AS yj_current,
        ROUND(SUM(
            CASE 
                WHEN month_num BETWEEN @start_month AND @end_month THEN yd 
                ELSE 0 
            END
        ), 2) AS yd_current
    FROM UnpivotedData
    GROUP BY kjnd, kmdm
),
-- 计算借贷方向
Calculations AS (
    SELECT 
        *,
        -- 期初借 = 期初净额（借-贷）的正值部分 + 起始月前的累计借
        ROUND(( (ncj_total - ncd_total + yj_begin - yd_begin) + 
               ABS(ncj_total - ncd_total + yj_begin - yd_begin) ) / 2, 2) AS begin_debit,
        -- 期初贷 = 期初净额（借-贷）的负值部分 + 起始月前的累计贷
        ROUND(( ( - (ncj_total - ncd_total + yj_begin - yd_begin) + 
                 ABS(ncj_total - ncd_total + yj_begin - yd_begin) ) ) / 2, 2) AS begin_credit,
        -- 期末借 = 期初借 + 本期借
        ROUND(( (ncj_total - ncd_total + yj_begin - yd_begin) + 
               ABS(ncj_total - ncd_total + yj_begin - yd_begin) ) / 2 + yj_current, 2) AS total_debit,
        -- 期末贷 = 期初贷 + 本期贷
        ROUND(( ( - (ncj_total - ncd_total + yj_begin - yd_begin) + 
                 ABS(ncj_total - ncd_total + yj_begin - yd_begin) ) ) / 2 + yd_current, 2) AS total_credit
    FROM AggregatedData
)
-- 最终结果展示
SELECT 
    C.kjnd AS 年份,
    C.kmdm AS 科目代码,
    X.kmmc AS 科目名称,
    C.begin_debit AS 期初借,
    C.begin_credit AS 期初贷,
    C.yj_current AS 本期借,
    C.yd_current AS 本期贷,
    C.total_debit AS 期末借,
    C.total_credit AS 期末贷
FROM Calculations AS C
LEFT JOIN GL_KMXX AS X 
    ON C.kmdm = X.kmdm 
    AND C.kjnd = X.kjnd
ORDER BY C.kmdm;