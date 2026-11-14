package net.matsudamper.serviceaccount.db

import java.sql.Connection
import org.sqlite.SQLiteConfig
import org.sqlite.SQLiteDataSource

/**
 * 操作ごとに接続を開く。SQLite の接続は軽く、接続を共有すると別スレッドのトランザクションが混ざる
 */
class Database(
    path: String,
) {
    private val dataSource =
        SQLiteDataSource(
            SQLiteConfig().apply {
                enforceForeignKeys(true)
                setJournalMode(SQLiteConfig.JournalMode.WAL)
                setSynchronous(SQLiteConfig.SynchronousMode.NORMAL)
                setBusyTimeout(BUSY_TIMEOUT_MILLIS)
                // 読んでから書くトランザクションで、書き込みロックへの昇格に失敗しないよう最初から取る
                setTransactionMode(SQLiteConfig.TransactionMode.IMMEDIATE)
            },
        ).apply {
            url = "jdbc:sqlite:$path"
        }

    fun <T> read(block: (Connection) -> T): T = dataSource.connection.use(block)

    fun <T> transaction(block: (Connection) -> T): T =
        dataSource.connection.use { connection ->
            connection.autoCommit = false
            try {
                block(connection).also { connection.commit() }
            } catch (e: Throwable) {
                connection.rollback()
                throw e
            }
        }

    fun migrate() {
        transaction { connection ->
            val currentVersion = connection.createStatement().use { it.executeQuery("PRAGMA user_version").use { result -> if (result.next()) result.getInt(1) else 0 } }
            MIGRATIONS
                .withIndex()
                .drop(currentVersion)
                .forEach { (index, resourceName) ->
                    statementsOf(resourceName).forEach { sql ->
                        connection.createStatement().use { it.executeUpdate(sql) }
                    }
                    connection.createStatement().use { it.executeUpdate("PRAGMA user_version = ${index + 1}") }
                }
        }
    }

    private fun statementsOf(resourceName: String): List<String> {
        val sql =
            checkNotNull(Database::class.java.classLoader.getResourceAsStream(resourceName)) { "$resourceName が無い" }
                .use { it.readBytes().decodeToString() }
        // マイグレーションに文字列リテラルの ; やトリガーを書かない前提で区切る
        return sql.split(';').map { it.trim() }.filter { it.isNotEmpty() }
    }

    private companion object {
        const val BUSY_TIMEOUT_MILLIS = 5_000

        /**
         * 順番が PRAGMA user_version になるので、追加は末尾にだけ行う
         */
        val MIGRATIONS: List<String> =
            listOf(
                "db/migration/0001_init.sql",
            )
    }
}
