using System;
using System.Data;
using System.Data.Common;
using System.Data.SqlServerCe;
using System.IO;
using woanware;

namespace threatexpertchecker
{

    /// <summary>
    /// Used for creating the SQL CE session database, creating new database connections etc
    /// </summary>
    public class Db
    {
        #region SQL_TABLE_HASHES
        private const string SQL_TABLE_HASHES = @"CREATE TABLE [Hashes] (
  [Id] bigint NOT NULL IDENTITY (1,1)
, [Md5] nvarchar(32)
, [UpdateDate] datetime
, [Info] ntext NULL
);";
        #endregion

        #region SQL_TABLE_HASHES_PK
        private const string SQL_TABLE_HASHES_PK = @"ALTER TABLE [Hashes] ADD CONSTRAINT [Id_Hashes] PRIMARY KEY ([Id]);";
        #endregion

        #region SQL_ADD_INDEX
        private const string SQL_ADD_INDEX = @"CREATE UNIQUE INDEX [IX_{0}] ON [Hashes]
(
	[{0}] ASC
)";
        #endregion

        #region Public Methods
        /// <summary>
        /// 
        /// </summary>
        /// <param name="databasePath"></param>
        /// <returns></returns>
        public static string CreateDatabase(string databasePath)
        {
            try
            {
                string path = System.IO.Path.GetDirectoryName(databasePath);
                if (System.IO.Directory.Exists(path) == false)
                {
                    IO.CreateDirectory(path);
                }

                using (SqlCeEngine sqlCeEngine = new SqlCeEngine(GetConnectionString(databasePath)))
                {
                    sqlCeEngine.CreateDatabase();

                    using (SqlCeConnection connection = new SqlCeConnection(GetConnectionString(databasePath)))
                    {
                        connection.Open();

                        using (SqlCeCommand command = new SqlCeCommand(SQL_TABLE_HASHES, connection))
                        {
                            command.ExecuteNonQuery();
                        }

                        using (SqlCeCommand command = new SqlCeCommand(SQL_TABLE_HASHES_PK, connection))
                        {
                            command.ExecuteNonQuery();
                        }

                        using (SqlCeCommand command = new SqlCeCommand(string.Format(SQL_ADD_INDEX, "Md5"), connection))
                        {
                            command.ExecuteNonQuery();
                        }
                    }
                }

                return string.Empty;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public static string GetConnectionString(string databasePath)
        {
            return string.Format("DataSource=\"{0}\"; Max Database Size=4091", GetDbPath(databasePath));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public static DbConnection GetOpenConnection(string databasePath)
        {
            var connection = new SqlCeConnection(GetConnectionString(databasePath));
            connection.Open();

            return connection;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public static string GetDbPath(string databasePath)
        {
            //return System.IO.Path.Combine(Misc.GetUserDataDirectory(), Global.DB_FILE);
            return System.IO.Path.Combine(databasePath, Global.DB_FILE);
        }
        #endregion
    }
}
