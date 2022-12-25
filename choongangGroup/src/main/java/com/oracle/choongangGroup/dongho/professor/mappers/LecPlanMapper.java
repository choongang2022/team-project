package com.oracle.choongangGroup.dongho.professor.mappers;

import java.util.Map;
import java.util.Optional;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.annotations.UpdateProvider;

import com.oracle.choongangGroup.dongho.professor.lecturePlan.LecPlanDto;
import com.oracle.choongangGroup.dongho.professor.lecturePlan.LecPlanSql;

@Mapper
public interface LecPlanMapper {
	@Select("  SELECT * "
			+ "FROM   lec_plan "
			+ "WHERE  lec_id = #{id}")
	LecPlanDto findByLecId(@Param("id") Long id);
	
	int insertPlan(LecPlanDto lecPlanDto);
	
	@SelectProvider(type = LecPlanSql.class, method = "findByLecIdWithOptional")
	Optional<LecPlanDto> findByLecIdWithOptional(@Param("lec_id") Long lec_id);
	
	@UpdateProvider(type = LecPlanSql.class, method = "updatePlan")
	int updatePlan(LecPlanDto lecPlanDto);

	int deletePlanAndLec(@Param("lec_id") Long lec_id);
}
