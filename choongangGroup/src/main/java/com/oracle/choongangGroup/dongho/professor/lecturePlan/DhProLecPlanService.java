package com.oracle.choongangGroup.dongho.professor.lecturePlan;

import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface DhProLecPlanService {

	List<LecPlanLecDto> findByProfNameAndYearAndSemester(String profName, String year, String semester, String lecStatus);

	LecPlanDto     findLecPlanByLecId(Long id);

	List<LecPlanWeekDto> findLecPlanWeekByLecId(Long id);

	int insertPlan(LecPlanDto lecPlanDto);

	Object insertWeek(List<Map<Object, Object>> planWeekArray);

	Optional<LecPlanDto> findByLecIdWithOptional(Long lec_id);

	int updatePlan(LecPlanDto lecPlanDto);

	int updateWeek(List<Map<Object, Object>> planWeekArray);

	int deletePlanAndLec(Long lec_id);

}
