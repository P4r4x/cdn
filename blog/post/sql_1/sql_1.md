sql 笔记
===

### 系统表


#### mySQL

mySQL 中数据表的主要信息在 `information_schema` 中, 提供所有数据库、表、列、权限等元数据。`information_schema`中的所有表都是只读的。

>   假设要查找包含字段名为 `test` 的数据表, 那么执行的查询是:
>   ```sql
>   SELECT 
>       TABLE_SCHEMA AS '数据库名',
>       TABLE_NAME AS '表名',
>       COLUMN_NAME AS '字段名'
>   FROM 
>       information_schema.columns 
>   WHERE 
>       COLUMN_NAME = 'test' 
>   AND TABLE_SCHEMA = 'test_database'
>   ```

---

##### information_schema.tables

`information_schema.tables` 存放了所有表的基本信息,示例:

|TABLE_SCHEMA|TABLE_NAME|ENGINE|TABLE_ROWS|AVG_ROW_LENGTH
|----|----|----|----|----|
|mydb|users|InnoDB|1000|128|
|mydb|orders|InnoDB|5000|256|
|sys|sys_config|InnoDB|1|1024|

---

##### information_schema.columns

`information_schema.columns` 主要存放表中列字段的信息和属性, 例如该字段要求字符还是整数, 限长多少。示例:


|TABLE_SCHEMA|TABLE_NAME|COLUMN_NAME|DATA_TYPE|CHARACTER_MAXIMUM_LENGTH|IS_NULLABLE|COLUMN_DEFAULT|EXTRA|
|----|----|----|----|----|----|----|----|
|mydb|users|id|int|NULL|NO|NULL|auto_increment|
|mydb|users|name|varchar|255|YES|NULL||
|mydb|orders|amount|decimal|NULL|NO|0.00|	

而用户权限等数据存放在 `mysql` 表中。 

### SQL server

SQL server 下的系统表大致如下:

|系统表/视图|用途|所在数据库|
|----|----|----|
|sys.tables|用户表元数据|用户数据库|
|sys.columns|表的列定义|用户数据库|
|sys.indexes|索引定义|用户数据库|
|sys.objects|所有数据库对象|表、视图、存储过程等|用户数据库|
|sys.types|数据类型定义|用户数据库|
|sys.schemas|数据库架构（命名空间）|用户数据库|
|sys.dm_exec_sessions|当前会话信息|所有数据库|
|sys.dm_exec_connections|客户端连接信息|所有数据库|

