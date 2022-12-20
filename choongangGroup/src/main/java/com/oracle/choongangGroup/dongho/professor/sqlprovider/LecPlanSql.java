package com.oracle.choongangGroup.dongho.professor.sqlprovider;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.jdbc.SQL;

import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.LecPlanDto;

public class LecPlanSql {
	
	public String findByLecIdWithOptional(@Param("lec_id") Long lec_id) {
		SQL sql = new SQL() {{
			SELECT("lec_id");
			FROM("lec_plan");
			WHERE("lec_id = #{lec_id}");
		}};
		return sql.toString();
	}
	
	public String updatePlan(LecPlanDto lecPlanDto) {
		SQL sql = new SQL() {{
			UPDATE("lec_plan");
			SET("plan_goal          = #{plan_goal}");
			SET("plan_midterm_ratio = #{plan_midterm_ratio}");
			SET("plan_final_ratio   = #{plan_final_ratio}");
			SET("plan_report_ratio  = #{plan_report_ratio}");
			SET("plan_attendance    = #{plan_attendance}");
			SET("plan_way           = #{plan_way}");
			SET("book_name          = #{book_name}");
			SET("book_author        = #{book_author}");
			SET("book_publisher     = #{book_publisher}");
			SET("book_year          = #{book_year}");
			SET("plan_eval_detail1  = #{plan_eval_detail1}");
			SET("plan_eval_detail2  = #{plan_eval_detail2}");
			WHERE("lec_id = #{lec_id}");
		}};
		return sql.toString();
	}
}
