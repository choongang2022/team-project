package com.oracle.choongangGroup.dongho.professor.lecturePlan;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartRequest;

import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.LecPlanDto;
import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.LecPlanLecDto;
import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.LecPlanWeekDto;
import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.PlanPdfDto;

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

	String generatePdf(PlanPdfDto planPdfDto, HttpServletRequest request) throws Exception;

	int uploadPlanFile(String lec_id, MultipartFile[] multipartFiles);

	Long isExistPlan(Long lec_id);

}
