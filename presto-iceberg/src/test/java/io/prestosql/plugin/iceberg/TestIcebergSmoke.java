/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.prestosql.plugin.iceberg;

import com.google.common.collect.ImmutableMap;
import io.prestosql.Session;
import io.prestosql.testing.AbstractTestIntegrationSmokeTest;
import io.prestosql.testing.MaterializedResult;
import io.prestosql.testing.QueryRunner;
import io.prestosql.testing.assertions.Assert;
import org.apache.iceberg.FileFormat;
import org.intellij.lang.annotations.Language;
import org.testng.annotations.Test;

import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.collect.Iterables.getOnlyElement;
import static io.prestosql.plugin.iceberg.IcebergQueryRunner.createIcebergQueryRunner;
import static io.prestosql.spi.type.VarcharType.VARCHAR;
import static io.prestosql.testing.MaterializedResult.resultBuilder;
import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

public class TestIcebergSmoke
        extends AbstractTestIntegrationSmokeTest
{
    private static final Pattern WITH_CLAUSE_EXTRACTER = Pattern.compile(".*(WITH\\s*\\([^)]*\\))\\s*$", Pattern.DOTALL);

    @Override
    protected QueryRunner createQueryRunner()
            throws Exception
    {
        return createIcebergQueryRunner(ImmutableMap.of());
    }

    @Test
    public void testShowCreateSchema()
    {
        assertThat(computeActual("SHOW CREATE SCHEMA tpch").getOnlyValue().toString())
                .matches("CREATE SCHEMA iceberg.tpch\n" +
                        "AUTHORIZATION USER user\n" +
                        "WITH \\(\n" +
                        "   location = '.*/iceberg_data/tpch'\n" +
                        "\\)");
    }

    @Test
    @Override
    public void testDescribeTable()
    {
        MaterializedResult expectedColumns = resultBuilder(getQueryRunner().getDefaultSession(), VARCHAR, VARCHAR, VARCHAR, VARCHAR)
                .row("orderkey", "bigint", "", "")
                .row("custkey", "bigint", "", "")
                .row("orderstatus", "varchar", "", "")
                .row("totalprice", "double", "", "")
                .row("orderdate", "date", "", "")
                .row("orderpriority", "varchar", "", "")
                .row("clerk", "varchar", "", "")
                .row("shippriority", "integer", "", "")
                .row("comment", "varchar", "", "")
                .build();
        MaterializedResult actualColumns = computeActual("DESCRIBE orders");
        Assert.assertEquals(actualColumns, expectedColumns);
    }

    @Override
    public void testShowCreateTable()
    {
        assertThat(computeActual("SHOW CREATE TABLE orders").getOnlyValue())
                .isEqualTo("CREATE TABLE iceberg.tpch.orders (\n" +
                        "   orderkey bigint,\n" +
                        "   custkey bigint,\n" +
                        "   orderstatus varchar,\n" +
                        "   totalprice double,\n" +
                        "   orderdate date,\n" +
                        "   orderpriority varchar,\n" +
                        "   clerk varchar,\n" +
                        "   shippriority integer,\n" +
                        "   comment varchar\n" +
                        ")\n" +
                        "WITH (\n" +
                        "   format = 'ORC'\n" +
                        ")");
    }

    @Test
    public void testDecimal()
    {
        testWithAllFileFormats((session, format) -> testDecimalForFormat(session, format));
    }

    private void testDecimalForFormat(Session session, FileFormat format)
    {
        testDecimalWithPrecisionAndScale(session, format, 1, 0);
        testDecimalWithPrecisionAndScale(session, format, 8, 6);
        testDecimalWithPrecisionAndScale(session, format, 9, 8);
        testDecimalWithPrecisionAndScale(session, format, 10, 8);

        testDecimalWithPrecisionAndScale(session, format, 18, 1);
        testDecimalWithPrecisionAndScale(session, format, 18, 8);
        testDecimalWithPrecisionAndScale(session, format, 18, 17);

        testDecimalWithPrecisionAndScale(session, format, 17, 16);
        testDecimalWithPrecisionAndScale(session, format, 18, 17);
        testDecimalWithPrecisionAndScale(session, format, 24, 10);
        testDecimalWithPrecisionAndScale(session, format, 30, 10);
        testDecimalWithPrecisionAndScale(session, format, 37, 26);
        testDecimalWithPrecisionAndScale(session, format, 38, 37);

        testDecimalWithPrecisionAndScale(session, format, 38, 17);
        testDecimalWithPrecisionAndScale(session, format, 38, 37);
    }

    private void testDecimalWithPrecisionAndScale(Session session, FileFormat format, int precision, int scale)
    {
        checkArgument(precision >= 1 && precision <= 38, "Decimal precision (%s) must be between 1 and 38 inclusive", precision);
        checkArgument(scale < precision && scale >= 0, "Decimal scale (%s) must be less than the precision (%s) and non-negative", scale, precision);

        String tableName = format("test_decimal_p%d_s%d", precision, scale);
        String decimalType = format("DECIMAL(%d,%d)", precision, scale);
        String beforeTheDecimalPoint = "12345678901234567890123456789012345678".substring(0, precision - scale);
        String afterTheDecimalPoint = "09876543210987654321098765432109876543".substring(0, scale);
        String decimalValue = format("%s.%s", beforeTheDecimalPoint, afterTheDecimalPoint);

        assertUpdate(session, format("CREATE TABLE %s (x %s) WITH (format = '%s')", tableName, decimalType, format.name()));
        assertUpdate(session, format("INSERT INTO %s (x) VALUES (CAST('%s' AS %s))", tableName, decimalValue, decimalType), 1);
        assertQuery(session, format("SELECT * FROM %s", tableName), format("SELECT CAST('%s' AS %s)", decimalValue, decimalType));
        dropTable(session, tableName);
    }

    @Test
    public void testParquetPartitionByTimestamp()
    {
        assertUpdate("CREATE TABLE test_parquet_partitioned_by_timestamp (_timestamp timestamp) " +
                "WITH (format = 'PARQUET', partitioning = ARRAY['_timestamp'])");
        testSelectOrPartitionedByTimestamp("test_parquet_partitioned_by_timestamp");
    }

    @Test
    public void testParquetSelectByTimestamp()
    {
        assertUpdate("CREATE TABLE test_parquet_select_by_timestamp (_timestamp timestamp) WITH (format = 'PARQUET')");
        testSelectOrPartitionedByTimestamp("test_parquet_select_by_timestamp");
    }

    @Test
    public void testOrcPartitionByTimestamp()
    {
        assertUpdate("CREATE TABLE test_orc_partitioned_by_timestamp (_timestamp timestamp) " +
                "WITH (format = 'ORC', partitioning = ARRAY['_timestamp'])");
        testSelectOrPartitionedByTimestamp("test_orc_partitioned_by_timestamp");
    }

    @Test
    public void testOrcSelectByTimestamp()
    {
        assertUpdate("CREATE TABLE test_orc_select_by_timestamp (_timestamp timestamp) " +
                "WITH (format = 'ORC')");
        testSelectOrPartitionedByTimestamp("test_orc_select_by_timestamp");
    }

    private void testSelectOrPartitionedByTimestamp(String tableName)
    {
        String select1 = "SELECT CAST('2017-05-01 10:12:34' AS TIMESTAMP) _timestamp";
        assertUpdate(format("INSERT INTO %s ", tableName) + select1, 1);
        String select2 = "SELECT CAST('2017-10-01 10:12:34' AS TIMESTAMP) _timestamp";
        assertUpdate(format("INSERT INTO %s " + select2, tableName), 1);
        String select3 = "SELECT CAST('2018-05-01 10:12:34' AS TIMESTAMP) _timestamp";
        assertUpdate(format("INSERT INTO %s " + select3, tableName), 1);
        assertQuery(format("SELECT COUNT(*) from %s", tableName), "SELECT 3");

        assertQuery(format("SELECT * from %s WHERE _timestamp = CAST('2017-05-01 10:12:34' AS TIMESTAMP)", tableName), select1);
        assertQuery(format("SELECT * from %s WHERE _timestamp < CAST('2017-06-01 10:12:34' AS TIMESTAMP)", tableName), select1);
        assertQuery(format("SELECT * from %s WHERE _timestamp = CAST('2017-10-01 10:12:34' AS TIMESTAMP)", tableName), select2);
        assertQuery(format("SELECT * from %s WHERE _timestamp > CAST('2017-06-01 10:12:34' AS TIMESTAMP) AND _timestamp < CAST('2018-05-01 10:12:34' AS TIMESTAMP)", tableName), select2);
        assertQuery(format("SELECT * from %s WHERE _timestamp = CAST('2018-05-01 10:12:34' AS TIMESTAMP)", tableName), select3);
        assertQuery(format("SELECT * from %s WHERE _timestamp > CAST('2018-01-01 10:12:34' AS TIMESTAMP)", tableName), select3);
        dropTable(getSession(), tableName);
    }

    @Test
    public void testCreatePartitionedTable()
    {
        testWithAllFileFormats(this::testCreatePartitionedTable);
    }

    private void testCreatePartitionedTable(Session session, FileFormat fileFormat)
    {
        @Language("SQL") String createTable = "" +
                "CREATE TABLE test_partitioned_table (" +
                "  _string VARCHAR" +
                ", _bigint BIGINT" +
                ", _integer INTEGER" +
                ", _real REAL" +
                ", _double DOUBLE" +
                ", _boolean BOOLEAN" +
                ", _decimal_short DECIMAL(3,2)" +
                ", _decimal_long DECIMAL(30,10)" +
                ", _timestamp TIMESTAMP" +
                ", _date DATE" +
                ") " +
                "WITH (" +
                "format = '" + fileFormat + "', " +
                "partitioning = ARRAY[" +
                "  '_string'," +
                "  '_integer'," +
                "  '_bigint'," +
                "  '_boolean'," +
                "  '_real'," +
                "  '_double'," +
                "  '_decimal_short', " +
                "  '_decimal_long'," +
                "  '_timestamp'," +
                "  '_date']" +
                ")";

        assertUpdate(session, createTable);

        MaterializedResult result = computeActual("SELECT * from test_partitioned_table");
        assertEquals(result.getRowCount(), 0);

        @Language("SQL") String select = "" +
                "SELECT" +
                " 'foo' _string" +
                ", CAST(123 AS BIGINT) _bigint" +
                ", 456 _integer" +
                ", CAST('123.45' AS REAL) _real" +
                ", CAST('3.14' AS DOUBLE) _double" +
                ", true _boolean" +
                ", CAST('3.14' AS DECIMAL(3,2)) _decimal_short" +
                ", CAST('12345678901234567890.0123456789' AS DECIMAL(30,10)) _decimal_long" +
                ", CAST('2017-05-01 10:12:34' AS TIMESTAMP) _timestamp" +
                ", CAST('2017-05-01' AS DATE) _date";

        assertUpdate(session, "INSERT INTO test_partitioned_table " + select, 1);
        assertQuery(session, "SELECT * from test_partitioned_table", select);
        assertQuery(session, "" +
                        "SELECT * FROM test_partitioned_table WHERE" +
                        " 'foo' = _string" +
                        " AND 456 = _integer" +
                        " AND CAST(123 AS BIGINT) = _bigint" +
                        " AND true = _boolean" +
                        " AND CAST('3.14' AS DECIMAL(3,2)) = _decimal_short" +
                        " AND CAST('12345678901234567890.0123456789' AS DECIMAL(30,10)) = _decimal_long" +
                        " AND CAST('2017-05-01 10:12:34' AS TIMESTAMP) = _timestamp" +
                        " AND CAST('2017-05-01' AS DATE) = _date",
                select);

        dropTable(session, "test_partitioned_table");
    }

    @Test
    public void testCreatePartitionedTableWithNestedTypes()
    {
        testWithAllFileFormats(this::testCreatePartitionedTableWithNestedTypes);
    }

    private void testCreatePartitionedTableWithNestedTypes(Session session, FileFormat fileFormat)
    {
        @Language("SQL") String createTable = "" +
                "CREATE TABLE test_partitioned_table_nested_type (" +
                "  _string VARCHAR" +
                ", _struct ROW(_field1 INT, _field2 VARCHAR)" +
                ", _date DATE" +
                ") " +
                "WITH (" +
                "format = '" + fileFormat + "', " +
                "partitioning = ARRAY['_date']" +
                ")";

        assertUpdate(session, createTable);

        dropTable(session, "test_partitioned_table_nested_type");
    }

    @Test
    public void testPartitionedTableWithNullValues()
    {
        testWithAllFileFormats(this::testPartitionedTableWithNullValues);
    }

    private void testPartitionedTableWithNullValues(Session session, FileFormat fileFormat)
    {
        @Language("SQL") String createTable = "" +
                "CREATE TABLE test_partitioned_table_with_null_values (" +
                "  _string VARCHAR" +
                ", _bigint BIGINT" +
                ", _integer INTEGER" +
                ", _real REAL" +
                ", _double DOUBLE" +
                ", _boolean BOOLEAN" +
                ", _decimal_short DECIMAL(3,2)" +
                ", _decimal_long DECIMAL(30,10)" +
                ", _timestamp TIMESTAMP" +
                ", _date DATE" +
                ") " +
                "WITH (" +
                "format = '" + fileFormat + "', " +
                "partitioning = ARRAY[" +
                "  '_string'," +
                "  '_integer'," +
                "  '_bigint'," +
                "  '_boolean'," +
                "  '_real'," +
                "  '_double'," +
                "  '_decimal_short', " +
                "  '_decimal_long'," +
                "  '_timestamp'," +
                "  '_date']" +
                ")";

        assertUpdate(session, createTable);

        MaterializedResult result = computeActual("SELECT * from test_partitioned_table_with_null_values");
        assertEquals(result.getRowCount(), 0);

        @Language("SQL") String select = "" +
                "SELECT" +
                " null _string" +
                ", null _bigint" +
                ", null _integer" +
                ", null _real" +
                ", null _double" +
                ", null _boolean" +
                ", null _decimal_short" +
                ", null _decimal_long" +
                ", null _timestamp" +
                ", null _date";

        assertUpdate(session, "INSERT INTO test_partitioned_table_with_null_values " + select, 1);
        assertQuery(session, "SELECT * from test_partitioned_table_with_null_values", select);
        dropTable(session, "test_partitioned_table_with_null_values");
    }

    @Test
    public void testCreatePartitionedTableAs()
    {
        testWithAllFileFormats(this::testCreatePartitionedTableAs);
    }

    private void testCreatePartitionedTableAs(Session session, FileFormat fileFormat)
    {
        @Language("SQL") String createTable = "" +
                "CREATE TABLE test_create_partitioned_table_as " +
                "WITH (" +
                "format = '" + fileFormat + "', " +
                "partitioning = ARRAY['ORDER_STATUS', 'Ship_Priority', 'Bucket(order_key,9)']" +
                ") " +
                "AS " +
                "SELECT orderkey AS order_key, shippriority AS ship_priority, orderstatus AS order_status " +
                "FROM tpch.tiny.orders";

        assertUpdate(session, createTable, "SELECT count(*) from orders");

        String createTableSql = format("" +
                        "CREATE TABLE %s.%s.%s (\n" +
                        "   order_key bigint,\n" +
                        "   ship_priority integer,\n" +
                        "   order_status varchar\n" +
                        ")\n" +
                        "WITH (\n" +
                        "   format = '" + fileFormat + "',\n" +
                        "   partitioning = ARRAY['order_status','ship_priority','bucket(order_key, 9)']\n" +
                        ")",
                getSession().getCatalog().get(),
                getSession().getSchema().get(),
                "test_create_partitioned_table_as");

        MaterializedResult actualResult = computeActual("SHOW CREATE TABLE test_create_partitioned_table_as");
        assertEquals(getOnlyElement(actualResult.getOnlyColumnAsSet()), createTableSql);

//        assertEquals(partitions.size(), 3);

        assertQuery(session, "SELECT * from test_create_partitioned_table_as", "SELECT orderkey, shippriority, orderstatus FROM orders");

        dropTable(session, "test_create_partitioned_table_as");
    }

    @Test
    public void testColumnComments()
    {
        Session session = getSession();
        assertUpdate(session, "CREATE TABLE test_column_comments (_bigint BIGINT COMMENT 'test column comment')");

        assertQuery(session, "SHOW COLUMNS FROM test_column_comments",
                "VALUES ('_bigint', 'bigint', '', 'test column comment')");

        dropTable(session, "test_column_comments");
    }

    @Test
    public void testTableComments()
    {
        Session session = getSession();
        String createTableTemplate = "" +
                        "CREATE TABLE iceberg.tpch.test_table_comments (\n" +
                        "   _x bigint\n" +
                        ")\n" +
                        "COMMENT '%s'\n" +
                        "WITH (\n" +
                        "   format = 'ORC'\n" +
                        ")";
        String createTableSql = format(createTableTemplate, "test table comment");
        assertUpdate(createTableSql);
        MaterializedResult resultOfCreate = computeActual("SHOW CREATE TABLE test_table_comments");
        assertEquals(getOnlyElement(resultOfCreate.getOnlyColumnAsSet()), createTableSql);

        assertUpdate("COMMENT ON TABLE test_table_comments IS 'different test table comment'");
        MaterializedResult resultOfCommentChange = computeActual("SHOW CREATE TABLE test_table_comments");
        String afterChangeSql = format(createTableTemplate, "different test table comment");
        assertEquals(getOnlyElement(resultOfCommentChange.getOnlyColumnAsSet()), afterChangeSql);

        String createTableWithoutComment = "" +
                "CREATE TABLE iceberg.tpch.test_table_comments (\n" +
                "   _x bigint\n" +
                ")\n" +
                "WITH (\n" +
                "   format = 'ORC'\n" +
                ")";
        assertUpdate("COMMENT ON TABLE test_table_comments IS NULL");
        MaterializedResult resultOfRemovingComment = computeActual("SHOW CREATE TABLE test_table_comments");
        assertEquals(getOnlyElement(resultOfRemovingComment.getOnlyColumnAsSet()), createTableWithoutComment);

        dropTable(session, "test_table_comments");
    }

    @Test
    public void testRollbackSnapshot()
    {
        Session session = getSession();
        MaterializedResult result = computeActual("SHOW SCHEMAS FROM system");
        assertUpdate(session, "CREATE TABLE test_rollback (col0 INTEGER, col1 BIGINT)");
        long afterCreateTableId = getLatestSnapshotId();

        assertUpdate(session, "INSERT INTO test_rollback (col0, col1) VALUES (123, CAST(987 AS BIGINT))", 1);
        long afterFirstInsertId = getLatestSnapshotId();

        assertUpdate(session, "INSERT INTO test_rollback (col0, col1) VALUES (456, CAST(654 AS BIGINT))", 1);
        assertQuery(session, "SELECT * FROM test_rollback ORDER BY col0", "VALUES (123, CAST(987 AS BIGINT)), (456, CAST(654 AS BIGINT))");

        assertUpdate(format("CALL system.rollback_to_snapshot('tpch', 'test_rollback', %s)", afterFirstInsertId));
        assertQuery(session, "SELECT * FROM test_rollback ORDER BY col0", "VALUES (123, CAST(987 AS BIGINT))");

        assertUpdate(format("CALL system.rollback_to_snapshot('tpch', 'test_rollback', %s)", afterCreateTableId));
        assertEquals((long) computeActual(session, "SELECT COUNT(*) FROM test_rollback").getOnlyValue(), 0);

        dropTable(session, "test_rollback");
    }

    private long getLatestSnapshotId()
    {
        return (long) computeActual("SELECT snapshot_id FROM \"test_rollback$snapshots\" ORDER BY committed_at DESC LIMIT 1")
                .getOnlyValue();
    }

    @Test
    public void testInsertIntoNotNullColumn()
    {
        assertUpdate("CREATE TABLE test_not_null_table (c1 INTEGER, c2 INTEGER NOT NULL)");
        assertUpdate("INSERT INTO test_not_null_table (c2) VALUES (2)", 1);
        assertQuery("SELECT * FROM test_not_null_table", "VALUES (NULL, 2)");
        assertQueryFails("INSERT INTO test_not_null_table (c1) VALUES (1)", "NULL value not allowed for NOT NULL column: c2");
        assertUpdate("DROP TABLE IF EXISTS test_not_null_table");

        assertUpdate("CREATE TABLE test_commuted_not_null_table (a BIGINT, b BIGINT NOT NULL)");
        assertUpdate("INSERT INTO test_commuted_not_null_table (b) VALUES (2)", 1);
        assertQuery("SELECT * FROM test_commuted_not_null_table", "VALUES (NULL, 2)");
        assertQueryFails("INSERT INTO test_commuted_not_null_table (b, a) VALUES (NULL, 3)", "NULL value not allowed for NOT NULL column: b");
        assertUpdate("DROP TABLE IF EXISTS test_commuted_not_null_table");
    }

    @Test
    public void testSchemaEvolution()
    {
        // Schema evolution should be id based
        testWithAllFileFormats(this::testSchemaEvolution);
    }

    private void testSchemaEvolution(Session session, FileFormat fileFormat)
    {
        assertUpdate(session, "CREATE TABLE test_schema_evolution_drop_end (col0 INTEGER, col1 INTEGER, col2 INTEGER) WITH (format = '" + fileFormat + "')");
        assertUpdate(session, "INSERT INTO test_schema_evolution_drop_end VALUES (0, 1, 2)", 1);
        assertQuery(session, "SELECT * FROM test_schema_evolution_drop_end", "VALUES(0, 1, 2)");
        assertUpdate(session, "ALTER TABLE test_schema_evolution_drop_end DROP COLUMN col2");
        assertQuery(session, "SELECT * FROM test_schema_evolution_drop_end", "VALUES(0, 1)");
        assertUpdate(session, "ALTER TABLE test_schema_evolution_drop_end ADD COLUMN col2 INTEGER");
        assertQuery(session, "SELECT * FROM test_schema_evolution_drop_end", "VALUES(0, 1, NULL)");
        assertUpdate(session, "INSERT INTO test_schema_evolution_drop_end VALUES (3, 4, 5)", 1);
        assertQuery(session, "SELECT * FROM test_schema_evolution_drop_end", "VALUES(0, 1, NULL), (3, 4, 5)");
        dropTable(session, "test_schema_evolution_drop_end");

        assertUpdate(session, "CREATE TABLE test_schema_evolution_drop_middle (col0 INTEGER, col1 INTEGER, col2 INTEGER) WITH (format = '" + fileFormat + "')");
        assertUpdate(session, "INSERT INTO test_schema_evolution_drop_middle VALUES (0, 1, 2)", 1);
        assertQuery(session, "SELECT * FROM test_schema_evolution_drop_middle", "VALUES(0, 1, 2)");
        assertUpdate(session, "ALTER TABLE test_schema_evolution_drop_middle DROP COLUMN col1");
        assertQuery(session, "SELECT * FROM test_schema_evolution_drop_middle", "VALUES(0, 2)");
        assertUpdate(session, "ALTER TABLE test_schema_evolution_drop_middle ADD COLUMN col1 INTEGER");
        assertUpdate(session, "INSERT INTO test_schema_evolution_drop_middle VALUES (3, 4, 5)", 1);
        assertQuery(session, "SELECT * FROM test_schema_evolution_drop_middle", "VALUES(0, 2, NULL), (3, 4, 5)");
        dropTable(session, "test_schema_evolution_drop_middle");
    }

    @Test
    private void testCreateTableLike()
    {
        Session session = getSession();
        assertUpdate(session, "CREATE TABLE test_create_table_like_original (col1 INTEGER, aDate DATE) WITH(format = 'PARQUET', partitioning = ARRAY['aDate'])");
        assertEquals(getTablePropertiesString("test_create_table_like_original"), "WITH (\n" +
                "   format = 'PARQUET',\n" +
                "   partitioning = ARRAY['adate']\n" +
                ")");

        assertUpdate(session, "CREATE TABLE test_create_table_like_copy0 (LIKE test_create_table_like_original, col2 INTEGER)");
        assertUpdate(session, "INSERT INTO test_create_table_like_copy0 (col1, aDate, col2) VALUES (1, CAST('1950-06-28' AS DATE), 3)", 1);
        assertQuery(session, "SELECT * from test_create_table_like_copy0", "VALUES(1, CAST('1950-06-28' AS DATE), 3)");
        dropTable(session, "test_create_table_like_copy0");

        assertUpdate(session, "CREATE TABLE test_create_table_like_copy1 (LIKE test_create_table_like_original)");
        assertEquals(getTablePropertiesString("test_create_table_like_copy1"), "WITH (\n" +
                "   format = 'ORC'\n" +
                ")");
        dropTable(session, "test_create_table_like_copy1");

        assertUpdate(session, "CREATE TABLE test_create_table_like_copy2 (LIKE test_create_table_like_original EXCLUDING PROPERTIES)");
        assertEquals(getTablePropertiesString("test_create_table_like_copy2"), "WITH (\n" +
                "   format = 'ORC'\n" +
                ")");
        dropTable(session, "test_create_table_like_copy2");

        assertUpdate(session, "CREATE TABLE test_create_table_like_copy3 (LIKE test_create_table_like_original INCLUDING PROPERTIES)");
        assertEquals(getTablePropertiesString("test_create_table_like_copy3"), "WITH (\n" +
                "   format = 'PARQUET',\n" +
                "   partitioning = ARRAY['adate']\n" +
                ")");
        dropTable(session, "test_create_table_like_copy3");

        assertUpdate(session, "CREATE TABLE test_create_table_like_copy4 (LIKE test_create_table_like_original INCLUDING PROPERTIES) WITH (format = 'ORC')");
        assertEquals(getTablePropertiesString("test_create_table_like_copy4"), "WITH (\n" +
                "   format = 'ORC',\n" +
                "   partitioning = ARRAY['adate']\n" +
                ")");
        dropTable(session, "test_create_table_like_copy4");

        dropTable(session, "test_create_table_like_original");
    }

    private String getTablePropertiesString(String tableName)
    {
        MaterializedResult showCreateTable = computeActual("SHOW CREATE TABLE " + tableName);
        String createTable = (String) getOnlyElement(showCreateTable.getOnlyColumnAsSet());
        Matcher matcher = WITH_CLAUSE_EXTRACTER.matcher(createTable);
        if (matcher.matches()) {
            return matcher.group(1);
        }
        else {
            return null;
        }
    }

    @Test
    public void testPredicating()
    {
        testWithAllFileFormats(this::testPredicating);
    }

    private void testPredicating(Session session, FileFormat fileFormat)
    {
        assertUpdate(session, "CREATE TABLE test_predicating_on_real (col REAL) WITH (format = '" + fileFormat + "')");
        assertUpdate(session, "INSERT INTO test_predicating_on_real VALUES 1.2", 1);
        assertQuery(session, "SELECT * FROM test_predicating_on_real WHERE col = 1.2", "VALUES 1.2");
        dropTable(session, "test_predicating_on_real");
    }

    @Test
    public void testDateTransforms()
    {
        testWithAllFileFormats(this::testHourTransformForFormat);
        testWithAllFileFormats(this::testDayTransformForFormat);
        testWithAllFileFormats(this::testMonthTransformForFormat);
        testWithAllFileFormats(this::testYearTransformForFormat);
    }

    private void testHourTransformForFormat(Session session, FileFormat format)
    {
        String select = "SELECT d_hour, row_count, d.min AS d_min, d.max AS d_max, b.min AS b_min, b.max AS b_max FROM \"test_hour_transform$partitions\"";

        assertUpdate(session, format("CREATE TABLE test_hour_transform (d TIMESTAMP, b BIGINT)" +
                " WITH (format = '%s', partitioning = ARRAY['hour(d)'])", format.name()));

        String insertSql = "INSERT INTO test_hour_transform VALUES" +
                "(TIMESTAMP '2015-01-01 10:01:23', 1)," +
                "(TIMESTAMP '2015-01-01 10:10:02', 2)," +
                "(TIMESTAMP '2015-01-01 10:55:00', 3)," +
                "(TIMESTAMP '2015-05-15 12:05:01', 4)," +
                "(TIMESTAMP '2015-05-15 12:21:02', 5)," +
                "(TIMESTAMP '2015-02-21 13:11:11', 6)," +
                "(TIMESTAMP '2015-02-21 13:12:12', 7)";
        assertUpdate(session, insertSql, 7);

        assertQuery(session, "SELECT COUNT(*) FROM \"test_hour_transform$partitions\"", "SELECT 3");

        assertQuery(session, "SELECT b FROM test_hour_transform WHERE hour(d) = 10 ORDER BY d", "SELECT b FROM (VALUES (1), (2), (3)) AS t(b)");
        // 394460 = (2015 - 1970) * 365 * 24 + leap day hours + 10
        // Parquet has min/max for timestamps but ORC does not.
        String expectedQuery = format == FileFormat.PARQUET ?
                "VALUES(394460, 3, TIMESTAMP '2015-01-01 10:01:23', TIMESTAMP '2015-01-01 10:55:00', 1, 3)" :
                "VALUES(394460, 3, NULL, NULL, 1, 3)";
        assertQuery(session, select + " WHERE d_hour = 394460", expectedQuery);

        assertQuery(session, "SELECT b FROM test_hour_transform WHERE hour(d) = 12", "SELECT b FROM (VALUES (4), (5)) AS t(b)");
        expectedQuery = format == FileFormat.PARQUET ?
                "VALUES(397679, 2, TIMESTAMP '2015-05-15 12:05:01', TIMESTAMP '2015-05-15 12:21:02', 4, 5)" :
                "VALUES(397679, 2, NULL, NULL, 4, 5)";
        assertQuery(session, select + " WHERE d_hour = 397679", expectedQuery);

        assertQuery(session, "SELECT b FROM test_hour_transform WHERE hour(d) = 13", "SELECT b FROM (VALUES (6), (7)) AS t(b)");
        expectedQuery = format == FileFormat.PARQUET ?
                "VALUES(395687, 2, TIMESTAMP '2015-02-21 13:11:11', TIMESTAMP '2015-02-21 13:12:12', 6, 7)" :
                "VALUES(395687, 2, NULL, NULL, 6, 7)";
        assertQuery(session, select + " WHERE d_hour = 395687", expectedQuery);

        dropTable(session, "test_hour_transform");
    }

    private void testDayTransformForFormat(Session session, FileFormat format)
    {
        String select = "SELECT d_day, row_count, d.min AS d_min, d.max AS d_max, b.min AS b_min, b.max AS b_max FROM \"test_day_transform$partitions\"";

        assertUpdate(session, format("CREATE TABLE test_day_transform (d DATE, b BIGINT)" +
                " WITH (format = '%s', partitioning = ARRAY['day(d)'])", format.name()));

        String insertSql = "INSERT INTO test_day_transform VALUES" +
                "(DATE '2015-01-13', 1)," +
                "(DATE '2015-01-13', 2)," +
                "(DATE '2015-01-13', 3)," +
                "(DATE '2015-05-15', 4)," +
                "(DATE '2015-05-15', 5)," +
                "(DATE '2015-02-21', 6)," +
                "(DATE '2015-02-21', 7)";
        assertUpdate(session, insertSql, 7);

        assertQuery(session, "SELECT COUNT(*) FROM \"test_day_transform$partitions\"", "SELECT 3");

        assertQuery(session, "SELECT b FROM test_day_transform WHERE day(d) = 13", "SELECT b FROM (VALUES (1), (2), (3)) AS t(b)");
        assertQuery(session, select + " WHERE d_day = date '2015-01-13'", "VALUES(DATE '2015-01-13', 3, DATE '2015-01-13', DATE '2015-01-13', 1, 3)");

        assertQuery(session, "SELECT b FROM test_day_transform WHERE day(d) = 15", "SELECT b FROM (VALUES (4), (5)) AS t(b)");
        assertQuery(session, select + " WHERE d_day = date '2015-05-15'", "VALUES(DATE '2015-05-15', 2, DATE '2015-05-15', DATE '2015-05-15', 4, 5)");

        assertQuery(session, "SELECT b FROM test_day_transform WHERE day(d) = 21", "SELECT b FROM (VALUES (6), (7)) AS t(b)");
        assertQuery(session, select + " WHERE d_day = date '2015-02-21'", "VALUES(DATE '2015-02-21', 2, DATE '2015-02-21', DATE '2015-02-21', 6, 7)");

        dropTable(session, "test_day_transform");
    }

    private void testMonthTransformForFormat(Session session, FileFormat format)
    {
        String select = "SELECT d_month, row_count, d.min AS d_min, d.max AS d_max, b.min AS b_min, b.max AS b_max FROM \"test_month_transform$partitions\"";

        assertUpdate(session, format("CREATE TABLE test_month_transform (d DATE, b BIGINT)" +
                " WITH (format = '%s', partitioning = ARRAY['month(d)'])", format.name()));

        String insertSql = "INSERT INTO test_month_transform VALUES" +
                "(DATE '2020-06-16', 1)," +
                "(DATE '2020-06-28', 2)," +
                "(DATE '2020-06-06', 3)," +
                "(DATE '2020-07-18', 4)," +
                "(DATE '2020-07-28', 5)";
        assertUpdate(session, insertSql, 5);

        assertQuery(session, "SELECT COUNT(*) FROM \"test_month_transform$partitions\"", "SELECT 2");

        assertQuery(session, "SELECT b FROM test_month_transform WHERE month(d) = 6", "SELECT b FROM (VALUES (1), (2), (3)) AS t(b)");
        // 605 = (2020 - 1970) * 12 + (6 - 1)
        assertQuery(session, select + " WHERE d_month = 605", "VALUES(605, 3, DATE '2020-06-06', DATE '2020-06-28', 1, 3)");

        assertQuery(session, "SELECT b FROM test_month_transform WHERE month(d) = 7", "SELECT b FROM (VALUES (4), (5)) AS t(b)");
        assertQuery(session, select + " WHERE d_month = 606", "VALUES(606, 2, DATE '2020-07-18', DATE '2020-07-28', 4, 5)");

        dropTable(session, "test_month_transform");
    }

    private void testYearTransformForFormat(Session session, FileFormat format)
    {
        String select = "SELECT d_year, row_count, d.min AS d_min, d.max AS d_max, b.min AS b_min, b.max AS b_max FROM \"test_year_transform$partitions\"";

        assertUpdate(session, format("CREATE TABLE test_year_transform (d DATE, b BIGINT)" +
                " WITH (format = '%s', partitioning = ARRAY['year(d)'])", format.name()));

        String insertSql = "INSERT INTO test_year_transform VALUES" +
                "(DATE '2015-01-13', 1)," +
                "(DATE '2015-06-16', 2)," +
                "(DATE '2015-07-28', 3)," +
                "(DATE '2016-05-15', 4)," +
                "(DATE '2016-06-06', 5)," +
                "(DATE '2020-02-21', 6)," +
                "(DATE '2020-11-10', 7)";
        assertUpdate(session, insertSql, 7);

        assertQuery(session, "SELECT COUNT(*) FROM \"test_year_transform$partitions\"", "SELECT 3");

        assertQuery(session, "SELECT b FROM test_year_transform WHERE year(d) = 2015", "SELECT b FROM (VALUES (1), (2), (3)) AS t(b)");
        // 45 = 2015 - 1970
        assertQuery(session, select + " WHERE d_year = 45", "VALUES(45, 3, DATE '2015-01-13', DATE '2015-07-28', 1, 3)");

        assertQuery(session, "SELECT b FROM test_year_transform WHERE year(d) = 2016", "SELECT b FROM (VALUES (4), (5)) AS t(b)");
        assertQuery(session, select + " WHERE d_year = 46", "VALUES(46, 2, DATE '2016-05-15', DATE '2016-06-06', 4, 5)");

        assertQuery(session, "SELECT b FROM test_year_transform WHERE year(d) = 2020", "SELECT b FROM (VALUES (6), (7)) AS t(b)");
        assertQuery(session, select + " WHERE d_year = 50", "VALUES(50, 2, DATE '2020-02-21', DATE '2020-11-10', 6, 7)");

        dropTable(session, "test_year_transform");
    }

    @Test
    public void testTruncateTransform()
    {
        testWithAllFileFormats(this::testTruncateTransformsForFormat);
    }

    private void testTruncateTransformsForFormat(Session session, FileFormat format)
    {
        String select = "SELECT d_trunc, row_count, d.min AS d_min, d.max AS d_max, b.min AS b_min, b.max AS b_max FROM \"test_truncate_transform$partitions\"";

        assertUpdate(session, format("CREATE TABLE test_truncate_transform (d VARCHAR, b BIGINT)" +
                " WITH (format = '%s', partitioning = ARRAY['truncate(d, 2)'])", format.name()));

        String insertSql = "INSERT INTO test_truncate_transform VALUES" +
                "('abcd', 1)," +
                "('abxy', 2)," +
                "('ab598', 3)," +
                "('mommy', 4)," +
                "('moscow', 5)," +
                "('Greece', 6)," +
                "('Grozny', 7)";
        assertUpdate(session, insertSql, 7);

        assertQuery(session, "SELECT COUNT(*) FROM \"test_truncate_transform$partitions\"", "SELECT 3");

        assertQuery(session, "SELECT b FROM test_truncate_transform WHERE substring(d, 1, 2) = 'ab'", "SELECT b FROM (VALUES (1), (2), (3)) AS t(b)");
        assertQuery(session, select + " WHERE d_trunc = 'ab'", "VALUES('ab', 3, 'ab598', 'abxy', 1, 3)");

        assertQuery(session, "SELECT b FROM test_truncate_transform WHERE substring(d, 1, 2) = 'mo'", "SELECT b FROM (VALUES (4), (5)) AS t(b)");
        assertQuery(session, select + " WHERE d_trunc = 'mo'", "VALUES('mo', 2, 'mommy', 'moscow', 4, 5)");

        assertQuery(session, "SELECT b FROM test_truncate_transform WHERE substring(d, 1, 2) = 'Gr'", "SELECT b FROM (VALUES (6), (7)) AS t(b)");
        assertQuery(session, select + " WHERE d_trunc = 'Gr'", "VALUES('Gr', 2, 'Greece', 'Grozny', 6, 7)");

        dropTable(session, "test_truncate_transform");
    }

    @Test
    public void testBucketTransform()
    {
        testWithAllFileFormats(this::testBucketTransformsForFormat);
    }

    private void testBucketTransformsForFormat(Session session, FileFormat format)
    {
        String select = "SELECT d_bucket, row_count, d.min AS d_min, d.max AS d_max, b.min AS b_min, b.max AS b_max FROM \"test_bucket_transform$partitions\"";

        assertUpdate(session, format("CREATE TABLE test_bucket_transform (d VARCHAR, b BIGINT)" +
                " WITH (format = '%s', partitioning = ARRAY['bucket(d, 2)'])", format.name()));
        String insertSql = "INSERT INTO test_bucket_transform VALUES" +
                "('abcd', 1)," +
                "('abxy', 2)," +
                "('ab598', 3)," +
                "('mommy', 4)," +
                "('moscow', 5)," +
                "('Greece', 6)," +
                "('Grozny', 7)";
        assertUpdate(session, insertSql, 7);

        assertQuery(session, "SELECT COUNT(*) FROM \"test_bucket_transform$partitions\"", "SELECT 2");

        assertQuery(session, select + " WHERE d_bucket = 0", "VALUES(0, 3, 'Grozny', 'mommy', 1, 7)");

        assertQuery(session, select + " WHERE d_bucket = 1", "VALUES(1, 4, 'Greece', 'moscow', 2, 6)");

        dropTable(session, "test_bucket_transform");
    }

    private void testWithAllFileFormats(BiConsumer<Session, FileFormat> test)
    {
        test.accept(getSession(), FileFormat.PARQUET);
        test.accept(getSession(), FileFormat.ORC);
    }

    private void dropTable(Session session, String table)
    {
        assertUpdate(session, "DROP TABLE " + table);
        assertFalse(getQueryRunner().tableExists(session, table));
    }

    @Test
    public void testCreateNestedPartitionedTable()
    {
        @Language("SQL") String createTable = "" +
            "CREATE TABLE test_nested_table (" +
                " bool BOOLEAN" +
                ", int INTEGER" +
                ", arr ARRAY(VARCHAR)" +
                ", big BIGINT" +
                ", rl REAL" +
                ", dbl DOUBLE" +
                ", mp MAP(INTEGER, VARCHAR)" +
                ", dec DECIMAL(5,2)" +
                ", vc VARCHAR" +
                ", vb VARBINARY" +
                ", ts TIMESTAMP" +
                ", str ROW(id INTEGER , vc VARCHAR)" +
                ", dt DATE)" +
                " WITH (partitioning = ARRAY['int'])";

        Session session = getSession();
        assertUpdate(session, createTable);

        assertUpdate(session, "INSERT INTO test_nested_table " +
                " select true, 1, array['uno', 'dos', 'tres'], BIGINT '1', REAL '1.0', DOUBLE '1.0', map(array[1,2,3,4], array['ek','don','teen','char'])," +
                " CAST(1.0 as DECIMAL(5,2))," +
                " 'one', VARBINARY 'binary0/1values',\n" +
                " cast(current_timestamp as TIMESTAMP), (CAST(ROW(null, 'this is a random value') AS ROW(int, varchar))), current_date", 1);
        MaterializedResult result = computeActual("SELECT * from test_nested_table");
        assertEquals(result.getRowCount(), 1);

        dropTable(session, "test_nested_table");

        @Language("SQL") String createTable2 = "" +
            "CREATE TABLE test_nested_table (" +
                " int INTEGER" +
                ", arr ARRAY(ROW(id INTEGER, vc VARCHAR))" +
                ", big BIGINT" +
                ", rl REAL" +
                ", dbl DOUBLE" +
                ", mp MAP(INTEGER, ARRAY(VARCHAR))" +
                ", dec DECIMAL(5,2)" +
                ", str ROW(id INTEGER, vc VARCHAR, arr ARRAY(INTEGER))" +
                ", vc VARCHAR)" +
                " WITH (partitioning = ARRAY['int'])";

        assertUpdate(session, createTable2);

        assertUpdate(session, "INSERT INTO test_nested_table " +
                " select 1, array[cast(row(1, null) as row(int, varchar)), cast(row(2, 'dos') as row(int, varchar))], BIGINT '1', REAL '1.0', DOUBLE '1.0', " +
                "map(array[1,2], array[array['ek', 'one'], array['don', 'do', 'two']]), CAST(1.0 as DECIMAL(5,2)), " +
                "CAST(ROW(1, 'this is a random value', null) AS ROW(int, varchar, array(int))), 'one'", 1);
        result = computeActual("SELECT * from test_nested_table");
        assertEquals(result.getRowCount(), 1);

        @Language("SQL") String createTable3 = "" +
            "CREATE TABLE test_nested_table2 WITH (partitioning = ARRAY['int']) as select * from test_nested_table";

        assertUpdate(session, createTable3, 1);

        result = computeActual("SELECT * from test_nested_table2");
        assertEquals(result.getRowCount(), 1);

        dropTable(session, "test_nested_table");
        dropTable(session, "test_nested_table2");
    }
}
