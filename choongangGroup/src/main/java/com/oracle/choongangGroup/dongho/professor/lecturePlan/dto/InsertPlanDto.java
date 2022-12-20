package com.oracle.choongangGroup.dongho.professor.lecturePlan.dto;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import lombok.Data;

@Data
public class InsertPlanDto {
	private LecPlanDto lecPlanDto;
	private List<Map<Object, Object>> planWeekArray;
}
