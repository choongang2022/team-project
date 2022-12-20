package com.oracle.choongangGroup.dongho.professor.lecturePlan.dto;

import java.util.List;
import java.util.Map;

import lombok.Data;

@Data
public class LecPlanDto {
	private Long   lec_id;
	private String plan_goal;
	private String plan_midterm_ratio;
	private String plan_final_ratio;
	private String plan_report_ratio;
	private String plan_attendance;
	private String plan_way;
	private String book_name;
	private String book_author;
	private String book_publisher;
	private String book_year;
	private String plan_eval_category1;
	private String plan_eval_category2;
	private String plan_eval_detail1;
	private String plan_eval_detail2;
	
	private List<Map<Object, Object>> planWeekArray;
}
