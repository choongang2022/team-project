package com.oracle.choongangGroup.dongho.professor.lecturePlan.dto;

import lombok.Data;

@Data
public class LecPlanWeekDto {
	private Long   lec_id;
	private Long   week;
	private String week_detail;
}