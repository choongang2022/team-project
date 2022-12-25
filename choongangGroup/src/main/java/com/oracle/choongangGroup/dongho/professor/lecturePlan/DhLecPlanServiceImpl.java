package com.oracle.choongangGroup.dongho.professor.lecturePlan;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.stereotype.Service;

import com.oracle.choongangGroup.dongho.professor.mappers.LecPlanMapper;
import com.oracle.choongangGroup.dongho.professor.mappers.LecPlanWeekMapper;
import com.oracle.choongangGroup.dongho.professor.mappers.LectureMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class DhLecPlanServiceImpl implements DhProLecPlanService{
	private final LectureMapper     lectureMapper;
	private final LecPlanMapper     lecPlanMapper;
	private final LecPlanWeekMapper lecPlanWeekMapper;
	
	@Override
	public List<LecPlanLecDto> findByProfNameAndYearAndSemester(String profName, String year, String semester, String lecStatus) {
		return lectureMapper.findByProfNameAndYearAndSemester(profName, year, semester, lecStatus);
	}

	@Override
	public LecPlanDto findLecPlanByLecId(Long id) {
		log.info("findLecPlanByLecId select start");
		return lecPlanMapper.findByLecId(id);
	}

	@Override
	public List<LecPlanWeekDto> findLecPlanWeekByLecId(Long id) {
		log.info("findLecPlanWeekByLecId select start");
		return lecPlanWeekMapper.findByLecId(id);
	}

	@Override
	public int insertPlan(LecPlanDto lecPlanDto) {
		int resultPlan = lecPlanMapper.insertPlan(lecPlanDto);
		System.out.println(resultPlan);
		return resultPlan;
	}

	@Override
	public Object insertWeek(List<Map<Object, Object>> planWeekArray) {
		int resultWeek = lecPlanWeekMapper.insertWeek(planWeekArray);
		return resultWeek;
	}

	@Override
	public Optional<LecPlanDto> findByLecIdWithOptional(Long lec_id) {
		
		return lecPlanMapper.findByLecIdWithOptional(lec_id);
	}

	@Override
	public int updatePlan(LecPlanDto lecPlanDto) {
		return lecPlanMapper.updatePlan(lecPlanDto);
	}

	@Override
	public int updateWeek(List<Map<Object, Object>> planWeekArray) {
		return lecPlanWeekMapper.updateWeek(planWeekArray);
	}

	@Override
	public int deletePlanAndLec(Long lec_id) {
		return lecPlanMapper.deletePlanAndLec(lec_id);
	}

}
