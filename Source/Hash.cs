using System;
using NPoco;

namespace threatexpertchecker
{
    /// <summary>
    /// 
    /// </summary>
    [TableName("Hashes")]
    [PrimaryKey("Id")]
    public class Hash
    {
        [Column("Id")]
        public int Id { get; set; }
        [Column("Md5")]
        public string Md5 { get; set; }
        [Column("UpdateDate")]
        public DateTime UpdateDate { get; set; }
        [Column("Info")]
        public string Info { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public Hash()
        {
            Md5 = string.Empty;
            Info = string.Empty;
        }
    }
}
