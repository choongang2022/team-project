package com.oracle.choongangGroup.dongho.professor.sqlprovider;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.jdbc.SQL;

public class LectureSql {
	public String updateLecPlanFilePath(@Param("long_lec_id")      Long   long_lec_id, 
                                        @Param("originalFileName") String originalFileName, 
                                        @Param("dBSaveFile")       String dBSaveFile) {
		SQL sql = new SQL() {{
			UPDATE("lecture");
			SET   ("lec_file_name = #{originalFileName}");
			SET   ("lec_file_path = #{dBSaveFile}");
			WHERE ("lec_id        = #{long_lec_id}");
		}};
		return sql.toString();
	}
	
	public String findFilePathByLecId(@Param("lec_id") Long lec_id) {
		SQL sql = new SQL() {{
			SELECT("lec_file_path");
			FROM("lecture");
			WHERE("lec_id = #{lec_id}");
		}};
		return sql.toString();
	}
	
	
}
