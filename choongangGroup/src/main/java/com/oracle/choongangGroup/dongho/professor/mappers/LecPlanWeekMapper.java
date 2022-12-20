package com.oracle.choongangGroup.dongho.professor.mappers;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.UpdateProvider;

import com.oracle.choongangGroup.dongho.professor.lecturePlan.dto.LecPlanWeekDto;
import com.oracle.choongangGroup.dongho.professor.sqlprovider.LecPlanSql;

@Mapper
public interface LecPlanWeekMapper {
	@Select("  SELECT * "
			+ "FROM   lec_plan_week "
			+ "WHERE  lec_id = #{id}")
	List<LecPlanWeekDto> findByLecId(@Param("id") Long id);

	int insertWeek(List<Map<Object, Object>> planWeekArray);
	
	int updateWeek(List<Map<Object, Object>> planWeekArray);
}