package com.oracle.choongangGroup.dongho.professor.lecturePlan;

import java.util.List;

import lombok.Data;

@Data
public class ShowPlanDetailDto {
	private LecPlanDto     lec_plan;
	private List<LecPlanWeekDto> lec_plan_weekList;
}
