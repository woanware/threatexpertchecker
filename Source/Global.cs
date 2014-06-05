namespace threatexpertchecker
{
    public class Global
    {
        public delegate void HashCheckedEvent(Hash hash);

        #region Constants
        public const string DB_FILE = "te.db";
        #endregion

        /// <summary>
        /// 
        /// </summary>
        public enum Mode
        {
            Cache,
            Database,
            Live
        }
    }
}
